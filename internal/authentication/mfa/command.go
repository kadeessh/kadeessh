package mfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"
)

// The subcommand tree implemented here is intentionally scoped to
// read-only + reset operations that need only filesystem access to
// the storage backend. Full-featured enrollment (which requires
// bootstrapping the caddy module tree so the TOTP factor can run) is
// available via the in-band SSH wizard or the ssh.actors.mfa_enroll
// actor. A future PR can add `mfa enroll` here by starting caddy in
// provision-only mode.

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "mfa",
		Usage: "[list|status|reset] ...",
		Short: "Administer multi-factor authentication enrollment records",
		Long: `Inspect and manage MFA enrollment records stored under a filesystem-backed
Caddy storage location. Non-filesystem storage backends (S3, Consul, etc.)
are not supported by this command; use the in-band SSH enrollment wizard
for those, or edit records with a backend-appropriate tool.`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.AddCommand(mfaListCmd())
			cmd.AddCommand(mfaStatusCmd())
			cmd.AddCommand(mfaResetCmd())
		},
	})
}

// storageFlags are common to every subcommand.
type storageFlags struct {
	storageRoot string
	server      string
}

func addStorageFlags(cmd *cobra.Command, f *storageFlags) {
	cmd.Flags().StringVar(&f.storageRoot, "storage-root", "", "Path to the Caddy filesystem storage root (defaults to $XDG_DATA_HOME/caddy)")
	cmd.Flags().StringVar(&f.server, "server", "", "SSH server name (matches apps.ssh.servers.<name>)")
}

// resolveStorageRoot picks the storage root, defaulting to
// $XDG_DATA_HOME/caddy or the platform-appropriate fallback.
func resolveStorageRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "caddy"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving storage root: %w", err)
	}
	return filepath.Join(home, ".local", "share", "caddy"), nil
}

// cliMFADir returns the on-disk directory for a server's MFA records
// under a filesystem-backed Caddy storage root. It mirrors the layout
// used by the caddystore package; the constant is inlined here rather
// than exported from caddystore to keep that package's public surface
// minimal.
func cliMFADir(root, server string) string {
	return filepath.Join(root, "ssh", "mfa", server)
}

// resolveServer picks the server name to operate on. If explicit, use
// it. Otherwise, scan the MFA directory for the single server that
// has records; error out if zero or more than one is found.
func resolveServer(root, explicit string) (string, error) {
	if explicit != "" {
		if err := ValidateScopeComponent("server", explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	base := filepath.Join(root, "ssh", "mfa")
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("no MFA records found under storage root; specify --server explicitly")
		}
		return "", fmt.Errorf("scanning %s: %w", base, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	switch len(names) {
	case 0:
		return "", errors.New("no MFA records found; specify --server explicitly")
	case 1:
		return names[0], nil
	default:
		sort.Strings(names)
		return "", fmt.Errorf("multiple servers found (%s); specify --server explicitly", strings.Join(names, ", "))
	}
}

// loadRecordFromDisk reads and JSON-decodes an EnrollmentRecord
// directly from the filesystem, bypassing the Caddy storage
// abstraction. This is the tradeoff for supporting the CLI without
// a running daemon: it only works against filesystem-backed storage.
func loadRecordFromDisk(root, server, username string) (*EnrollmentRecord, error) {
	if err := ValidateScopeComponent("server", server); err != nil {
		return nil, err
	}
	if err := ValidateScopeComponent("username", username); err != nil {
		return nil, err
	}
	path := filepath.Join(cliMFADir(root, server), username+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec EnrollmentRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &rec, nil
}

// -- list -----------------------------------------------------------

func mfaListCmd() *cobra.Command {
	var f storageFlags
	c := &cobra.Command{
		Use:   "list",
		Short: "List MFA enrollment records for a server",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := resolveStorageRoot(f.storageRoot)
			if err != nil {
				return err
			}
			server, err := resolveServer(root, f.server)
			if err != nil {
				return err
			}
			entries, err := os.ReadDir(cliMFADir(root, server))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(cmd.OutOrStdout(), "no records for server %q\n", server)
					return nil
				}
				return err
			}
			type row struct {
				user       string
				enrolled   string
				factors    string
				lastUsed   string
				lockedInfo string
			}
			var rows []row
			for _, e := range entries {
				name := e.Name()
				if !strings.HasSuffix(name, ".json") || e.IsDir() {
					continue
				}
				user := strings.TrimSuffix(name, ".json")
				rec, err := loadRecordFromDisk(root, server, user)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping %s: %v\n", name, err)
					continue
				}
				factors := factorList(rec)
				enrolled := "no"
				if len(rec.Factors) > 0 {
					enrolled = rec.EnrolledAt.UTC().Format("2006-01-02")
				}
				lastUsed := "-"
				if !rec.LastUsedAt.IsZero() {
					lastUsed = rec.LastUsedAt.UTC().Format("2006-01-02")
				}
				locked := "-"
				if !rec.FailedAttempts.LockedUntil.IsZero() && time.Now().Before(rec.FailedAttempts.LockedUntil) {
					locked = "yes (until " + rec.FailedAttempts.LockedUntil.UTC().Format(time.RFC3339) + ")"
				}
				rows = append(rows, row{user: user, enrolled: enrolled, factors: factors, lastUsed: lastUsed, lockedInfo: locked})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].user < rows[j].user })

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-24s  %-12s  %-24s  %-12s  %s\n", "USER", "ENROLLED", "FACTORS", "LAST USED", "LOCKED")
			for _, r := range rows {
				fmt.Fprintf(w, "%-24s  %-12s  %-24s  %-12s  %s\n", r.user, r.enrolled, r.factors, r.lastUsed, r.lockedInfo)
			}
			return nil
		},
	}
	addStorageFlags(c, &f)
	return c
}

// -- status ---------------------------------------------------------

func mfaStatusCmd() *cobra.Command {
	var f storageFlags
	c := &cobra.Command{
		Use:   "status <username>",
		Short: "Show MFA enrollment status for a specific user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := resolveStorageRoot(f.storageRoot)
			if err != nil {
				return err
			}
			server, err := resolveServer(root, f.server)
			if err != nil {
				return err
			}
			rec, err := loadRecordFromDisk(root, server, args[0])
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(cmd.OutOrStdout(), "user %q has no MFA record on server %q\n", args[0], server)
					return nil
				}
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "user:          %s\n", rec.Username)
			fmt.Fprintf(w, "server:        %s\n", server)
			fmt.Fprintf(w, "enrolled:      %v\n", len(rec.Factors) > 0)
			if !rec.EnrolledAt.IsZero() {
				fmt.Fprintf(w, "enrolled_at:   %s\n", rec.EnrolledAt.UTC().Format(time.RFC3339))
			}
			if !rec.FirstSeenAt.IsZero() {
				fmt.Fprintf(w, "first_seen_at: %s\n", rec.FirstSeenAt.UTC().Format(time.RFC3339))
			}
			if !rec.LastUsedAt.IsZero() {
				fmt.Fprintf(w, "last_used_at:  %s\n", rec.LastUsedAt.UTC().Format(time.RFC3339))
			}
			fmt.Fprintf(w, "factors:       %s\n", factorList(rec))
			fmt.Fprintf(
				w, "failed:        %d (window since %s)\n",
				rec.FailedAttempts.Count,
				zeroOr(rec.FailedAttempts.WindowStart),
			)
			if !rec.FailedAttempts.LockedUntil.IsZero() {
				fmt.Fprintf(w, "locked_until:  %s\n", rec.FailedAttempts.LockedUntil.UTC().Format(time.RFC3339))
			}
			return nil
		},
	}
	addStorageFlags(c, &f)
	return c
}

// -- reset ----------------------------------------------------------

func mfaResetCmd() *cobra.Command {
	var f storageFlags
	var yes bool
	c := &cobra.Command{
		Use:   "reset <username>",
		Short: "Delete a user's MFA enrollment record",
		Long: `Delete the user's MFA enrollment record so they will be treated as
unenrolled on their next login. On next login the enrollment wizard will
run again (subject to the server's grace-period policy).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ValidateScopeComponent("username", args[0]); err != nil {
				return err
			}
			root, err := resolveStorageRoot(f.storageRoot)
			if err != nil {
				return err
			}
			server, err := resolveServer(root, f.server)
			if err != nil {
				return err
			}
			path := filepath.Join(cliMFADir(root, server), args[0]+".json")
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(cmd.OutOrStdout(), "user %q has no record to reset\n", args[0])
				return nil
			}
			if !yes {
				fmt.Fprintf(cmd.OutOrStderr(), "This will permanently delete the enrollment record for user %q on server %q.\nRe-run with --yes to confirm.\n", args[0], server)
				return errors.New("aborted: confirmation required")
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed record for %q on server %q\n", args[0], server)
			return nil
		},
	}
	addStorageFlags(c, &f)
	c.Flags().BoolVar(&yes, "yes", false, "Confirm destructive operation")
	return c
}

// -- helpers --------------------------------------------------------

func factorList(rec *EnrollmentRecord) string {
	if len(rec.Factors) == 0 {
		return "-"
	}
	names := make([]string, 0, len(rec.Factors))
	for k := range rec.Factors {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func zeroOr(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}
