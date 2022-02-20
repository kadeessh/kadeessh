package adapter

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestAdapt(t *testing.T) {

	// load the list of test files from the dir
	files, err := filepath.Glob("./*.txt")
	if err != nil {
		t.Errorf("failed to read caddyfile_adapt dir: %s", err)
	}

	// prep a regexp to fix strings on windows
	winNewlines := regexp.MustCompile(`\r?\n`)

	for _, f := range files {

		data, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("failed to read the file '%s': %s", f, err)
		}

		// split the sshd_config (first) and JSON (second) parts
		parts := strings.Split(string(data), "----------")
		sshd_config, json := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		// replace windows newlines in the json with unix newlines
		json = winNewlines.ReplaceAllString(json, "\n")

		// run the test
		ok := caddytest.CompareAdapt(t, f, sshd_config, "sshd_config", json)
		if !ok {
			t.Errorf("failed to adapt '%s'", f)
		}
	}
}
