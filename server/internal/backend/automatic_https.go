package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

const acmeALPN = "acme-tls/1"

// Bind issuance and ARI requests (including timer-triggered renewals) to the
// server lifetime. Closing one instance never stops another instance's cache.
type serverACMEIssuer struct {
	*certmagic.ACMEIssuer
	root context.Context
}

func (i serverACMEIssuer) linked(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(i.root, cancel)
	if i.root.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
func (i serverACMEIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	ctx, cancel := i.linked(ctx)
	defer cancel()
	return i.ACMEIssuer.Issue(ctx, csr)
}
func (i serverACMEIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	ctx, cancel := i.linked(ctx)
	defer cancel()
	return i.ACMEIssuer.PreCheck(ctx, names, interactive)
}
func (i serverACMEIssuer) GetRenewalInfo(ctx context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	ctx, cancel := i.linked(ctx)
	defer cancel()
	return i.ACMEIssuer.GetRenewalInfo(ctx, cert)
}

type automaticHTTPS struct {
	ctx                    context.Context
	renewAtStart           bool
	config                 *certmagic.Config
	issuer                 *certmagic.ACMEIssuer
	cache                  *certmagic.Cache
	subject, challengeName string
	isIP                   bool
	ready                  chan struct{}
	readyOnce, closeOnce   sync.Once
}

func newAutomaticHTTPS(ctx context.Context, c Config, port int, log func(map[string]any)) (result *automaticHTTPS, err error) {
	m := &automaticHTTPS{ctx: ctx, subject: c.ACMEDomain, challengeName: c.ACMEDomain, ready: make(chan struct{})}
	if ip, e := netip.ParseAddr(c.ACMEDomain); e == nil {
		m.isIP = true
		a := ip.As4()
		m.challengeName = netip.AddrFrom4([4]byte{a[3], a[2], a[1], a[0]}).String() + ".in-addr.arpa"
	}
	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		Capacity: 1, Logger: zap.NewNop(), RenewCheckInterval: 5 * time.Minute,
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return m.config, nil
		},
	})
	defer func() {
		if err != nil {
			m.close()
		}
	}()
	m.config = certmagic.New(m.cache, certmagic.Config{
		Storage:           &certmagic.FileStorage{Path: filepath.Join(c.ACMECache, "certmagic")},
		DefaultServerName: c.ACMEDomain, Logger: zap.NewNop(),
		OnEvent: func(eventCtx context.Context, event string, _ map[string]any) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if log != nil && (event == "cert_obtaining" || event == "cert_obtained" || event == "cert_failed") {
				log(map[string]any{"event": "https", "state": event})
			}
			return nil
		},
	})
	profile := ""
	if m.isIP {
		profile = "shortlived"
	}
	m.issuer = certmagic.NewACMEIssuer(m.config, certmagic.ACMEIssuer{
		CA: certmagic.LetsEncryptProductionCA, Email: c.ACMEEmail, Agreed: c.ACMEAcceptTerms,
		Profile: profile, DisableHTTPChallenge: true, ListenHost: c.BindHost, AltTLSALPNPort: port,
		CertObtainTimeout: 60 * time.Second, Logger: zap.NewNop(),
	})
	m.config.Issuers = []certmagic.Issuer{serverACMEIssuer{m.issuer, ctx}}
	if err = m.importLegacyCache(ctx, c.ACMECache); err != nil {
		return nil, err
	}
	// Loading a valid cached certificate does not contact the ACME issuer.
	// First issuance runs only after Serve starts accepting ALPN validation.
	if cert, e := m.config.CacheManagedCertificate(ctx, m.subject); e == nil {
		m.renewAtStart = time.Until(cert.Leaf.NotAfter) < cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)/3
		if time.Now().Before(cert.Leaf.NotAfter) {
			m.readyOnce.Do(func() { close(m.ready) })
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("cannot load automatic certificate cache; preserve existing data")
	}
	return m, nil
}

func (m *automaticHTTPS) manage(ctx context.Context) {
	select {
	case <-m.ready:
		if !m.renewAtStart {
			return
		}
	default:
	}
	// Despite its name this method blocks while retrying. Own the worker and
	// cancel/wait for it on shutdown instead of detaching CertMagic global jobs.
	var err error
	if m.renewAtStart {
		err = m.config.RenewCertAsync(ctx, m.subject, false)
	} else {
		err = m.config.ObtainCertAsync(ctx, m.subject)
	}
	if err != nil {
		return
	}
	if _, err := m.config.CacheManagedCertificate(ctx, m.subject); err == nil {
		m.readyOnce.Do(func() { close(m.ready) })
	}
}
func (m *automaticHTTPS) close() { m.closeOnce.Do(func() { m.cache.Stop() }) }

func (m *automaticHTTPS) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1", acmeALPN},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if err := m.ctx.Err(); err != nil {
				return nil, err
			}
			challenge := len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acmeALPN
			wanted := m.subject
			if challenge {
				wanted = m.challengeName
			}
			if !strings.EqualFold(hello.ServerName, wanted) && !(m.isIP && !challenge && hello.ServerName == "") {
				return nil, errors.New("unconfigured TLS subject")
			}
			if !challenge {
				select {
				case <-m.ready:
				case <-m.ctx.Done():
					return nil, m.ctx.Err()
				case <-hello.Context().Done():
					return nil, hello.Context().Err()
				}
			}
			return m.config.GetCertificate(hello)
		},
	}
}

// Migrate the old autocert PEM without deleting it. Only a matching, valid
// certificate/key pair is imported; incomplete or foreign files are preserved.
func (m *automaticHTTPS) importLegacyCache(ctx context.Context, oldRoot string) error {
	storage := m.config.Storage
	issuer := m.config.Issuers[0].IssuerKey()
	meta := certmagic.StorageKeys.SiteMeta(issuer, m.subject)
	lockKey := "legacy-import-" + m.subject
	if e := storage.Lock(ctx, lockKey); e != nil {
		return errors.New("cannot lock certificate cache migration")
	}
	defer storage.Unlock(context.Background(), lockKey)
	if storage.Exists(ctx, meta) {
		return nil
	}
	path := filepath.Join(oldRoot, m.subject)
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) && !m.isIP {
		path += "+rsa"
		info, e = os.Lstat(path)
	}
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || !info.Mode().IsRegular() {
		return errors.New("legacy certificate cache must be a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return errors.New("cannot read legacy certificate cache")
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 512*1024+1))
	if e != nil || len(raw) > 512*1024 {
		return errors.New("invalid legacy certificate cache")
	}
	var certPEM, keyPEM []byte
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			return errors.New("invalid legacy certificate PEM")
		}
		raw = rest
		if block.Type == "CERTIFICATE" {
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		} else if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			keyPEM = append(keyPEM, pem.EncodeToMemory(block)...)
		} else {
			return errors.New("unexpected legacy certificate PEM block")
		}
	}
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil || len(pair.Certificate) == 0 {
		return errors.New("invalid legacy certificate/key pair")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.VerifyHostname(m.subject) != nil {
		return errors.New("legacy certificate does not match configured address")
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil
	}
	metadata, e := json.Marshal(certmagic.CertificateResource{SANs: []string{m.subject}})
	if e != nil {
		return e
	}
	for _, item := range []struct {
		key  string
		data []byte
	}{
		{certmagic.StorageKeys.SitePrivateKey(issuer, m.subject), keyPEM},
		{certmagic.StorageKeys.SiteCert(issuer, m.subject), certPEM}, {meta, metadata},
	} {
		if e = storage.Store(ctx, item.key, item.data); e != nil {
			return errors.New("cannot migrate legacy certificate cache")
		}
	}
	return nil
}
