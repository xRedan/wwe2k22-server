package backend

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Preserve the cause for platform-specific sharing retries without including
// filesystem paths or credentials in ordinary startup diagnostics.
type accessKeyIOError struct{ cause error }

func (e *accessKeyIOError) Error() string { return "cannot read access key file" }
func (e *accessKeyIOError) Unwrap() error { return e.cause }

func readPublishedKey(path string) (string, error) {
	for attempt := 0; ; attempt++ {
		key, err := readAccessKey(path)
		if err == nil || attempt >= 20 || !transientKeyIO(err) {
			return key, err
		}
		// Windows can expose the renamed directory entry before releasing
		// MoveFileEx's transient sharing lock. Never retry malformed contents.
		time.Sleep(10 * time.Millisecond)
	}
}

// LoadAccessKey never replaces an existing key, including an invalid one.
// A temporary file plus a no-replace publication makes simultaneous initial
// starts agree on one fully written key rather than observe partial writes.
func LoadAccessKey(path string, generate bool) (string, error) {
	if !generate {
		return readAccessKey(path)
	}
	if path == "" {
		return "", errors.New("generated access key requires a file path")
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return readPublishedKey(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", errors.New("cannot create access-key directory")
	}
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("cannot generate access key")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".access-key-*")
	if err != nil {
		return "", errors.New("cannot stage access key")
	}
	defer os.Remove(f.Name())
	_, writeErr := f.WriteString(hex.EncodeToString(bytes[:]) + "\n")
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.New("cannot persist access key")
	}
	if err = publishKeyFile(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return "", errors.New("cannot publish access key atomically")
	}
	return readPublishedKey(path)
}

func (c Config) serverTLSConfig() (*tls.Config, error) {
	if c.ACMEDomain != "" {
		if err := os.MkdirAll(c.ACMECache, 0700); err != nil {
			return nil, errors.New("cannot create certificate cache")
		}
		manager := &autocert.Manager{
			Cache: autocert.DirCache(c.ACMECache), Prompt: autocert.AcceptTOS,
			Email: c.ACMEEmail, HostPolicy: autocert.HostWhitelist(c.ACMEDomain),
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Keep the game's HTTP/1.1 wire contract; enable only the ACME
			// TLS-ALPN challenge in addition. No HTTP proxy or port 80 needed.
			NextProtos: []string{"http/1.1", acme.ALPNProto},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Enforce the exact domain even for certificates already cached.
				if !strings.EqualFold(hello.ServerName, c.ACMEDomain) {
					return nil, errors.New("unconfigured TLS domain")
				}
				return manager.GetCertificate(hello)
			},
		}, nil
	}
	if c.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, errors.New("cannot load TLS certificate/key")
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
	}
	return nil, nil
}
