package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestPrintAccessKeyWithoutListenersOrDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.key")
	t.Setenv("WWE_ACCESS_KEY_FILE", path)
	t.Setenv("WWE_GENERATE_ACCESS_KEY", "true")
	// Printing the operator key does not start listeners or initialize ACME.
	t.Setenv("WWE_BIND_HOST", "not-an-ip")
	var first string
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"--print-access-key"}, &stdout, &stderr); code != 0 {
			t.Fatal(code, stderr.String())
		}
		key := strings.TrimSpace(stdout.String())
		if len(key) != 64 || strings.ContainsAny(key, " \t\r\n") || stderr.Len() != 0 || first != "" && first != key {
			t.Fatal("operator key output invalid or changed")
		}
		first = key
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("operator command created unrelated state")
	}
	t.Setenv("WWE_ACCESS_KEY_FILE", "")
	t.Setenv("WWE_GENERATE_ACCESS_KEY", "false")
	var stdout, stderr bytes.Buffer
	if run([]string{"--print-access-key"}, &stdout, &stderr) != 1 || stdout.Len() != 0 {
		t.Fatal("unconfigured key must fail without secret output")
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
