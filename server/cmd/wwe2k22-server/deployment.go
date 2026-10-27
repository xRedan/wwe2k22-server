package main

import (
	"errors"
	"flag"
	"path/filepath"
	"wwe2k22-server/internal/backend"
)

// Profiles supply only missing values, below JSON, environment and CLI settings.
// The manual profile preserves the existing LAN/VPN and PEM configurations.
func applyDeploymentDefaults(fs *flag.FlagSet, c *backend.Config, profile string, networksConfigured bool) error {
	if profile == "manual" {
		return nil
	}
	if profile != "public" {
		return errors.New("deployment must be manual or public")
	}
	supplied := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { supplied[f.Name] = true })
	supplied["allow-network"] = supplied["allow-network"] || networksConfigured
	state := c.StateFile
	if state == "" {
		state = filepath.Join("data", "local-state.sqlite3")
	}
	defaults := map[string]string{
		"bind-host":            "0.0.0.0",
		"allow-network":        "0.0.0.0/0",
		"advertise-http-port":  "443",
		"state-file":           state,
		"vconline-matchmaking": "true",
		"custom-content":       "true",
		"access-key-file":      filepath.Join(filepath.Dir(state), "access.key"),
		"generate-access-key":  "true",
		"acme-cache":           filepath.Join(filepath.Dir(state), "acme"),
	}
	for name, value := range defaults {
		if !supplied[name] {
			if err := fs.Set(name, value); err != nil {
				return err
			}
		}
	}
	return nil
}
