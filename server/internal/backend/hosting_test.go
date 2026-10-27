package backend

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func hostedConfig(t *testing.T) Config {
	t.Helper()
	c := DefaultConfig()
	c.HTTPPort, c.UDPPort = 0, 0
	c.AdvertiseHTTPPort = 443
	c.AllowedNetworks = []string{"0.0.0.0/0"}
	c.ACMEDomain, c.ACMEEmail = "wwe.example.test", "admin@example.test"
	c.ACMEAcceptTerms, c.GenerateAccessKey = true, true
	c.ACMECache = filepath.Join(t.TempDir(), "acme")
	c.AccessKeyFile = filepath.Join(t.TempDir(), "access.key")
	return c
}

func TestAutomaticHTTPSSettings(t *testing.T) {
	c := hostedConfig(t)
	if err := c.Validate(); err != nil || c.HTTPHost != c.ACMEDomain {
		t.Fatal(c, err)
	}
	for _, item := range []struct {
		name   string
		change func(*Config)
	}{
		{"terms", func(c *Config) { c.ACMEAcceptTerms = false }},
		{"email", func(c *Config) { c.ACMEEmail = "invalid" }},
		{"email-name", func(c *Config) { c.ACMEEmail = "Name <admin@example.test>" }},
		{"cache", func(c *Config) { c.ACMECache = "" }},
		{"key-path", func(c *Config) { c.AccessKeyFile = "" }},
		{"wildcard", func(c *Config) { c.ACMEDomain = "*.example.test" }},
		{"ip", func(c *Config) { c.ACMEDomain = "203.0.113.1" }},
		{"url", func(c *Config) { c.ACMEDomain = "https://example.test" }},
		{"single-label", func(c *Config) { c.ACMEDomain = "localhost" }},
		{"different-host", func(c *Config) { c.HTTPHost = "other.example.test" }},
		{"pem", func(c *Config) { c.TLSCert, c.TLSKey = "cert.pem", "key.pem" }},
		{"restricted-network", func(c *Config) { c.AllowedNetworks = []string{"10.0.0.0/8"} }},
		{"wrong-public-port", func(c *Config) { c.AdvertiseHTTPPort = 8787 }},
		{"absent-domain", func(c *Config) { c.ACMEDomain = "" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			bad := hostedConfig(t)
			item.change(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("unsafe or unusable automatic HTTPS settings accepted")
			}
		})
	}
	plain := DefaultConfig()
	plain.GenerateAccessKey = true
	if err := plain.Validate(); err == nil {
		t.Fatal("key generation without a path accepted")
	}
}

func TestGeneratedKeyConcurrentAndPersistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "access.key")
	const count = 32
	keys, errs := make([]string, count), make([]error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() { defer wg.Done(); keys[i], errs[i] = LoadAccessKey(path, true) }()
	}
	wg.Wait()
	for i := range count {
		if errs[i] != nil || len(keys[i]) != 64 || keys[i] != keys[0] {
			t.Fatal("partial or replaced key", i, errs[i])
		}
	}
	for _, generate := range []bool{false, true} {
		if key, err := LoadAccessKey(path, generate); err != nil || key != keys[0] {
			t.Fatal("persistent key changed", err)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 || entries[0].Name() != "access.key" {
		t.Fatal("temporary key file leaked", entries)
	}
	if err := os.WriteFile(path, []byte("invalid-original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccessKey(path, true); err == nil {
		t.Fatal("invalid existing key accepted")
	}
	if content, _ := os.ReadFile(path); string(content) != "invalid-original" {
		t.Fatal("invalid existing key was overwritten")
	}
	if _, err := LoadAccessKey(filepath.Dir(path), true); err == nil {
		t.Fatal("directory accepted as key")
	}
	if _, err := LoadAccessKey("", true); err == nil {
		t.Fatal("empty generated-key path accepted")
	}
}

// Seed a synthetic valid cached certificate. This exercises the real autocert
// cache and TLS server without registering an account or contacting a CA.
func cacheHostedCertificate(t *testing.T, c Config) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: c.ACMEDomain},
		DNSNames: []string{c.ACMEDomain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.MkdirAll(c.ACMECache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.ACMECache, c.ACMEDomain), raw, 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return pool
}

func TestAutomaticHTTPSCacheAndProtocol(t *testing.T) {
	c := hostedConfig(t)
	pool := cacheHostedCertificate(t, c)
	for attempt := range 2 {
		s, err := NewServer(c)
		if err != nil {
			t.Fatal(err)
		}
		if s.Origin() != "https://wwe.example.test:443" {
			t.Fatal(s.Origin())
		}
		done := make(chan error, 1)
		go func() { done <- s.Serve() }()
		address := s.listener.Addr().String()
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: c.ACMEDomain},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		for _, item := range []struct{ path, wanted string }{
			{"/health", `"transport":"https"`}, {"/status", `"tls":true`},
			{"/discovery/v1/services", "https://wwe.example.test:443"},
		} {
			req, _ := http.NewRequest("GET", "https://wwe.example.test"+item.path, nil)
			req.Header.Set("X-WWE-Lab-Key", s.key)
			res, err := client.Do(req)
			if err != nil {
				s.Close()
				t.Fatal(attempt, item.path, err)
			}
			raw, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 200 || !bytes.Contains(raw, []byte(item.wanted)) {
				s.Close()
				t.Fatal(item.path, res.StatusCode, string(raw))
			}
		}
		res, err := client.Get("https://wwe.example.test/health")
		if err != nil {
			s.Close()
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			s.Close()
			t.Fatal("missing key accepted")
		}
		transport.CloseIdleConnections()
		s.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	// Even a cached unrelated SNI must fail without trying ACME.
	cfg, err := c.serverTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || !reflect.DeepEqual(cfg.NextProtos, []string{"http/1.1", "acme-tls/1"}) {
		t.Fatal("unexpected TLS/ALPN contract")
	}
	for _, name := range []string{"", "other.example.test", "wwe.example.test."} {
		if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); err == nil || !strings.Contains(err.Error(), "unconfigured") {
			t.Fatal("unconfigured SNI accepted", name, err)
		}
	}
}
