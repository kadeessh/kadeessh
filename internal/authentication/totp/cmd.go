package totp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"image/png"
	"io/ioutil"
	"strings"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/pquerna/otp/totp"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name: "totp-qr",
		Func: func(fl caddycmd.Flags) (int, error) {
			username := strings.TrimSpace(fl.String("username"))
			secret := []byte(strings.TrimSpace(fl.String("secret")))

			if username == "" || len(secret) == 0 {
				return caddy.ExitCodeFailedQuit, errors.New("username and secret cannot be empty")
			}

			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      fl.String("issuer"),
				AccountName: username,
				Secret:      secret,
				SecretSize:  uint(len(secret)),
			})
			if err != nil {
				return caddy.ExitCodeFailedQuit, err
			}
			var buf bytes.Buffer
			img, err := key.Image(200, 200)
			if err != nil {
				return caddy.ExitCodeFailedQuit, err
			}
			err = png.Encode(&buf, img)
			if err != nil {
				return caddy.ExitCodeFailedQuit, err
			}

			err = ioutil.WriteFile(fl.String("output"), buf.Bytes(), 0600)
			if err != nil {
				return caddy.ExitCodeFailedQuit, err
			}

			secretBase64 := base64.StdEncoding.EncodeToString(secret)
			fmt.Println(secretBase64)

			return caddy.ExitCodeSuccess, nil
		},
		Usage: "--secret <secret> --username <username> [--issuer <issuser>] [--output <output file name>]",
		Short: "Generates the QR code file for TOTP app configuration",
		Long: `
The command is used to generate the QR code to use with the TOTP apps (e.g. Google Authenticator) to
add the account. The command will generate the PNG file in addition to printing the secret in base64 encoding to be used
in the configuration file.

The flags --secret and --username are mandatory.

The --issuer flag defaults to "caddy-ssh".

The --output flag defaults to "qr.png".
`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("totp-qr", flag.ExitOnError)
			fs.String("secret", "", "The secret used to generate the TOTP")
			fs.String("username", "", "The username used to identify the user at login")
			fs.String("issuer", "caddy-ssh", "The issuer name to set in the OTP generator")
			fs.String("output", "qr.png", "The filename to output the QR to")
			return fs
		}(),
	})
}
