package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestHelpAndVersionWithoutServer(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatal(code, stderr.String())
		}
	}
}
func TestInvalidConfigurationRefused(t *testing.T) {
	for _, raw := range []string{`{"port":1,"port":2}`, `{"unknown":true}`, `{"allowed_networks":[]}`, `{"config":"other.json"}`, `{"bind_host":"0.0.0.0"}`} {
		file := filepath.Join(t.TempDir(), "settings.json")
		os.WriteFile(file, []byte(raw), 0600)
		var stdout, stderr bytes.Buffer
		if run([]string{"--config", file}, &stdout, &stderr) == 0 {
			t.Fatal("bad configuration accepted")
		}
	}
}
