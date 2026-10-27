package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
	"wwe2k22-server/internal/backend"
)

func profileFixture(t *testing.T) (*flag.FlagSet, *backend.Config, *networkFlags) {
	t.Helper()
	c := backend.DefaultConfig()
	var networks networkFlags
	fs := flag.NewFlagSet("profile-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.BindHost, "bind-host", c.BindHost, "")
	fs.Var(&networks, "allow-network", "")
	fs.IntVar(&c.AdvertiseHTTPPort, "advertise-http-port", 0, "")
	fs.StringVar(&c.StateFile, "state-file", "", "")
	fs.BoolVar(&c.Matchmaking, "vconline-matchmaking", false, "")
	fs.BoolVar(&c.CustomContent, "custom-content", false, "")
	fs.StringVar(&c.AccessKeyFile, "access-key-file", "", "")
	fs.BoolVar(&c.GenerateAccessKey, "generate-access-key", false, "")
	fs.StringVar(&c.ACMECache, "acme-cache", "", "")
	return fs, &c, &networks
}

func TestPublicDeploymentDefaultsAndOverrides(t *testing.T) {
	fs, c, networks := profileFixture(t)
	c.ACMEDomain, c.ACMEEmail = "wwe.example.test", "admin@example.test"
	c.ACMEAcceptTerms = true
	c.AdvertiseHost = "203.0.113.10"
	state := filepath.Join(t.TempDir(), "custom-state.sqlite3")
	if err := fs.Set("state-file", state); err != nil {
		t.Fatal(err)
	}
	if err := applyDeploymentDefaults(fs, c, "public", false); err != nil {
		t.Fatal(err)
	}
	c.AllowedNetworks = *networks
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyFile != filepath.Join(filepath.Dir(state), "access.key") || c.ACMECache != filepath.Join(filepath.Dir(state), "acme") ||
		c.BindHost != "0.0.0.0" || c.AdvertiseHTTPPort != 443 || !c.Matchmaking || !c.CustomContent || !c.GenerateAccessKey {
		t.Fatal("public defaults incomplete")
	}
	fs, c, networks = profileFixture(t)
	customKey := filepath.Join(t.TempDir(), "operator.key")
	for name, value := range map[string]string{"access-key-file": customKey, "custom-content": "false", "generate-access-key": "false", "bind-host": "127.0.0.1", "advertise-http-port": "9443"} {
		if err := fs.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	*networks = []string{"10.1.0.0/16"} // JSON/environment network settings bypass fs.Set.
	if err := applyDeploymentDefaults(fs, c, "public", true); err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyFile != customKey || c.CustomContent || c.GenerateAccessKey || c.BindHost != "127.0.0.1" || c.AdvertiseHTTPPort != 9443 || len(*networks) != 1 || (*networks)[0] != "10.1.0.0/16" {
		t.Fatal("explicit settings replaced by profile")
	}
	fs, c, networks = profileFixture(t)
	if err := applyDeploymentDefaults(fs, c, "public", true); err != nil {
		t.Fatal(err)
	}
	if len(*networks) != 0 {
		t.Fatal("empty explicit allowlist silently widened")
	}
	if c.ACMEAcceptTerms {
		t.Fatal("profile implicitly accepted certificate terms")
	}
}

func TestManualAndInvalidDeployment(t *testing.T) {
	fs, c, networks := profileFixture(t)
	if err := applyDeploymentDefaults(fs, c, "manual", false); err != nil {
		t.Fatal(err)
	}
	if c.BindHost != "127.0.0.1" || c.GenerateAccessKey || c.StateFile != "" || len(*networks) != 0 {
		t.Fatal("manual settings changed")
	}
	if err := applyDeploymentDefaults(fs, c, "unknown", false); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestPublicDeploymentEnvironmentAndCLI(t *testing.T) {
	t.Setenv("WWE_DEPLOYMENT", "public")
	state := filepath.Join(t.TempDir(), "state.sqlite3")
	t.Setenv("WWE_STATE_FILE", state)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--print-access-key"}, &stdout, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	key, err := backend.LoadAccessKey(filepath.Join(filepath.Dir(state), "access.key"), false)
	if err != nil || stdout.String() != key+"\n" {
		t.Fatal("profile did not provide persisted key")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--deployment=manual", "--print-access-key"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatal("CLI failed to override environment profile", code)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("key command created a database")
	}
}
