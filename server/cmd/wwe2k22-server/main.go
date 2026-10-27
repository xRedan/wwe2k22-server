package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"wwe2k22-server/internal/backend"
)

type networkFlags []string

func (n *networkFlags) String() string     { return strings.Join(*n, ",") }
func (n *networkFlags) Set(s string) error { *n = append(*n, s); return nil }
func run(args []string, stdout, stderr io.Writer) int {
	c := backend.DefaultConfig()
	fs := flag.NewFlagSet("wwe2k22-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var networks networkFlags
	var configPath, deployment string
	var networksConfigured bool
	var version, printAccessKey bool
	fs.StringVar(&configPath, "config", "", "JSON settings file; CLI overrides environment and JSON")
	fs.StringVar(&deployment, "deployment", "manual", "Defaults profile: manual or public (automatic HTTPS)")
	fs.BoolVar(&version, "version", false, "Print the Go backend version and exit")
	fs.BoolVar(&printAccessKey, "print-access-key", false, "Print the configured access key and exit without starting the server")
	fs.StringVar(&c.BindHost, "bind-host", c.BindHost, "HTTP/UDP listen IPv4")
	fs.StringVar(&c.AdvertiseHost, "advertise-host", "", "IPv4 reachable by all players")
	fs.StringVar(&c.HTTPHost, "http-host", "", "HTTP(S) hostname advertised to clients")
	fs.IntVar(&c.HTTPPort, "port", c.HTTPPort, "HTTP listen port")
	fs.IntVar(&c.UDPPort, "udp-port", c.UDPPort, "UDP relay listen port")
	fs.IntVar(&c.AdvertiseHTTPPort, "advertise-http-port", 0, "External HTTP port after forwarding")
	fs.IntVar(&c.AdvertiseUDPPort, "advertise-udp-port", 0, "External UDP port after forwarding")
	fs.Var(&networks, "allow-network", "Trusted IPv4 CIDR; repeat for several networks")
	fs.BoolVar(&c.Matchmaking, "vconline-matchmaking", false, "Enable native rooms, public directory and UDP relay")
	fs.BoolVar(&c.Catalog, "vconline-catalog", false, "Advertise native matchmaking service definitions")
	fs.BoolVar(&c.CustomContent, "custom-content", false, "Enable stored custom content and CAW image dependencies")
	fs.IntVar(&c.ContentQuotaMiB, "content-quota-mib", c.ContentQuotaMiB, "Logical content quota in MiB")
	fs.StringVar(&c.StateFile, "state-file", "", "Existing compatible SQLite state file")
	fs.IntVar(&c.MaxConnections, "max-connections", c.MaxConnections, "Maximum concurrent HTTP connections")
	fs.IntVar(&c.RoomIdleSeconds, "room-idle-seconds", c.RoomIdleSeconds, "Room participant inactivity timeout")
	fs.IntVar(&c.HTTPRate, "http-rate", c.HTTPRate, "HTTP connections per second and source IP")
	fs.IntVar(&c.UDPRate, "udp-rate", c.UDPRate, "UDP packets per second and source IP")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "PEM server certificate chain")
	fs.StringVar(&c.TLSKey, "tls-key", "", "PEM private key")
	fs.StringVar(&c.AccessKeyFile, "access-key-file", "", "Private shared access-key file")
	fs.BoolVar(&c.GenerateAccessKey, "generate-access-key", false, "Create a random persistent access key only if absent")
	fs.StringVar(&c.ACMEDomain, "acme-domain", "", "One DNS domain for automatic HTTPS via public TCP 443")
	fs.StringVar(&c.ACMEEmail, "acme-email", "", "ACME account contact email")
	fs.StringVar(&c.ACMECache, "acme-cache", "", "Persistent private certificate-cache directory")
	fs.BoolVar(&c.ACMEAcceptTerms, "acme-accept-terms", false, "Accept Let's Encrypt terms for automatic HTTPS")
	fs.StringVar(&c.LogFile, "log", "-", "Diagnostic JSONL file; - for console only")
	fs.BoolVar(&c.VerboseLog, "verbose-log", false, "Log successful request metadata too; never payloads or credentials")
	fs.StringVar(&c.ImportImages, "import-native-images", "", "Operator original-image capture manifest")
	fs.StringVar(&c.ImageOwner, "native-image-owner", "", "Local UserID of the original-image owner")
	fs.BoolVar(&c.UpgradeImages, "upgrade-native-images", false, "Explicitly upgrade matching legacy image packages")
	for i, arg := range args {
		if strings.HasPrefix(arg, "--config=") {
			configPath = strings.TrimPrefix(arg, "--config=")
		} else if strings.HasPrefix(arg, "-config=") {
			configPath = strings.TrimPrefix(arg, "-config=")
		} else if arg == "--config" || arg == "-config" {
			if i+1 < len(args) {
				configPath = args[i+1]
			}
		}
	}
	set := func(name string, value any) error {
		if name == "allow-network" {
			networksConfigured = true
			a, ok := value.([]any)
			if !ok || len(a) == 0 {
				return errors.New("allowed_networks must be a nonempty array")
			}
			networks = nil
			for _, v := range a {
				s, ok := v.(string)
				if !ok {
					return errors.New("invalid allowed network")
				}
				networks = append(networks, s)
			}
			return nil
		}
		if fs.Lookup(name) == nil {
			return fmt.Errorf("unknown server setting %q", name)
		}
		var text string
		switch v := value.(type) {
		case string:
			text = v
		case bool:
			text = strconv.FormatBool(v)
		case json.Number:
			text = string(v)
		default:
			return fmt.Errorf("invalid value type for %s", name)
		}
		return fs.Set(name, text)
	}
	if configPath != "" {
		f, e := os.Open(configPath)
		if e != nil {
			fmt.Fprintln(stderr, "Cannot read server configuration")
			return 2
		}
		raw, e := io.ReadAll(io.LimitReader(f, 128*1024+1))
		f.Close()
		if e != nil || len(raw) > 128*1024 {
			fmt.Fprintln(stderr, "Invalid server configuration size")
			return 2
		}
		m, e := backend.DecodeSettings(raw)
		if e != nil {
			fmt.Fprintln(stderr, "Invalid server configuration JSON")
			return 2
		}
		seenSettings := map[string]bool{}
		for k, v := range m {
			name := strings.ReplaceAll(k, "_", "-")
			if name == "config" || name == "version" || name == "print-access-key" {
				fmt.Fprintln(stderr, "Unsupported server setting:", name)
				return 2
			}
			if k == "allowed_networks" {
				name = "allow-network"
			}
			if seenSettings[name] {
				fmt.Fprintln(stderr, "Duplicate server setting:", name)
				return 2
			}
			seenSettings[name] = true
			if e = set(name, v); e != nil {
				fmt.Fprintln(stderr, e)
				return 2
			}
		}
		dir, e := filepath.Abs(filepath.Dir(configPath))
		if e != nil {
			fmt.Fprintln(stderr, "Invalid configuration directory")
			return 2
		}
		for _, p := range []*string{&c.StateFile, &c.TLSCert, &c.TLSKey, &c.AccessKeyFile, &c.ACMECache, &c.LogFile, &c.ImportImages} {
			if *p != "" && *p != "-" && !filepath.IsAbs(*p) {
				*p = filepath.Join(dir, *p)
			}
		}
	}
	env := map[string]string{"WWE_BIND_HOST": "bind-host", "WWE_ADVERTISE_HOST": "advertise-host", "WWE_HTTP_HOST": "http-host", "WWE_HTTP_PORT": "port", "WWE_UDP_PORT": "udp-port", "WWE_ADVERTISE_HTTP_PORT": "advertise-http-port", "WWE_ADVERTISE_UDP_PORT": "advertise-udp-port", "WWE_STATE_FILE": "state-file", "WWE_MAX_CONNECTIONS": "max-connections", "WWE_ROOM_IDLE_SECONDS": "room-idle-seconds", "WWE_HTTP_RATE": "http-rate", "WWE_UDP_RATE": "udp-rate", "WWE_TLS_CERT": "tls-cert", "WWE_TLS_KEY": "tls-key", "WWE_ACCESS_KEY_FILE": "access-key-file", "WWE_CUSTOM_CONTENT": "custom-content", "WWE_CONTENT_QUOTA_MIB": "content-quota-mib", "WWE_NATIVE_IMAGES_MANIFEST": "import-native-images", "WWE_NATIVE_IMAGE_OWNER": "native-image-owner", "WWE_UPGRADE_NATIVE_IMAGES": "upgrade-native-images", "WWE_VERBOSE_LOG": "verbose-log", "WWE_MATCHMAKING": "vconline-matchmaking", "WWE_LOG": "log"}
	env["WWE_DEPLOYMENT"] = "deployment"
	env["WWE_GENERATE_ACCESS_KEY"] = "generate-access-key"
	env["WWE_ACME_DOMAIN"] = "acme-domain"
	env["WWE_ACME_EMAIL"] = "acme-email"
	env["WWE_ACME_CACHE"] = "acme-cache"
	env["WWE_ACME_ACCEPT_TERMS"] = "acme-accept-terms"
	for variable, name := range env {
		if value, has := os.LookupEnv(variable); has && strings.TrimSpace(value) != "" {
			if e := fs.Set(name, strings.TrimSpace(value)); e != nil {
				fmt.Fprintln(stderr, "Invalid environment setting:", variable)
				return 2
			}
		}
	}
	if value, has := os.LookupEnv("WWE_ALLOWED_NETWORKS"); has {
		networksConfigured = true
		networks = nil
		for _, part := range strings.Split(value, ",") {
			if v := strings.TrimSpace(part); v != "" {
				networks = append(networks, v)
			}
		}
	}
	explicitNetworks := false
	for _, arg := range args {
		if arg == "--allow-network" || arg == "-allow-network" || strings.HasPrefix(arg, "--allow-network=") || strings.HasPrefix(arg, "-allow-network=") {
			explicitNetworks = true
		}
	}
	if explicitNetworks {
		networksConfigured = true
		networks = nil
	}
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected positional arguments")
		return 2
	}
	if version {
		fmt.Fprintln(stdout, backend.Release)
		return 0
	}
	if err := applyDeploymentDefaults(fs, &c, deployment, networksConfigured); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if printAccessKey {
		key, err := backend.LoadAccessKey(c.AccessKeyFile, c.GenerateAccessKey)
		if err != nil || key == "" {
			fmt.Fprintln(stderr, "Cannot read the configured access key")
			return 1
		}
		fmt.Fprintln(stdout, key)
		return 0
	}
	c.AllowedNetworks = networks
	server, e := backend.NewServer(c)
	if e != nil {
		fmt.Fprintln(stderr, "Server startup failed:", e)
		return 1
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	fmt.Fprintln(stdout, "WWE 2K22 Go server:", server.Origin())
	select {
	case <-ctx.Done():
		server.Close()
		if e := <-done; e != nil {
			fmt.Fprintln(stderr, "Server stopped after a listener error")
			return 1
		}
		return 0
	case e := <-done:
		if e != nil {
			fmt.Fprintln(stderr, "HTTP listener failed")
			return 1
		}
		return 0
	}
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
