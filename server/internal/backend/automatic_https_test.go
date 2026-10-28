package backend

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

type testACMEOrder struct {
	valid bool
	cert  []byte
	token string
}
type testACMECA struct {
	t                            *testing.T
	http                         *httptest.Server
	mu                           sync.Mutex
	orders                       map[int]*testACMEOrder
	next                         int
	thumb                        string
	host, kind, profile, address string
	key                          *ecdsa.PrivateKey
	root                         *x509.Certificate
	rootPEM                      []byte
	requests                     atomic.Int64
	validations                  atomic.Int64
}

// This CA validates the actual TLS-ALPN proof on the owned listener. It never
// contacts Let's Encrypt, and issues only synthetic certificates for tests.
func newTestACMECA(t *testing.T, host, address string) *testACMECA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(800), Subject: pkix.Name{CommonName: "WWE owned test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &testACMECA{t: t, orders: map[int]*testACMEOrder{}, host: host, kind: "dns", address: address, key: key, root: root, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	if net.ParseIP(host) != nil {
		ca.kind = "ip"
		ca.profile = "shortlived"
	}
	ca.http = httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.http.Close)
	return ca
}
func (ca *testACMECA) serve(w http.ResponseWriter, r *http.Request) {
	ca.requests.Add(1)
	w.Header().Set("Replay-Nonce", fmt.Sprintf("owned-test-nonce-%d", ca.requests.Load()))
	w.Header().Set("Content-Type", "application/json")
	var payload []byte
	if r.Method == "POST" {
		var jws struct{ Protected, Payload string }
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			ca.t.Error(err)
			http.Error(w, "invalid JWS", 400)
			return
		}
		var err error
		payload, err = base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			ca.t.Error(err)
			http.Error(w, "invalid payload", 400)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/account") {
			header, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
			var protected struct{ JWK map[string]json.RawMessage }
			_ = json.Unmarshal(header, &protected)
			if len(protected.JWK) > 0 {
				canonical, _ := json.Marshal(protected.JWK)
				sum := sha256.Sum256(canonical)
				ca.mu.Lock()
				ca.thumb = base64.RawURLEncoding.EncodeToString(sum[:])
				ca.mu.Unlock()
			}
		}
	}
	base := ca.http.URL
	respond := func(status int, v any) { w.WriteHeader(status); _ = json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/directory":
		respond(200, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order", "revokeCert": base + "/revoke", "keyChange": base + "/key-change", "meta": map[string]any{"termsOfService": base + "/terms", "profiles": map[string]string{"shortlived": base + "/profile"}}})
		return
	case "/nonce":
		w.WriteHeader(200)
		return
	case "/account", "/account/1":
		w.Header().Set("Location", base+"/account/1")
		respond(201, map[string]any{"status": "valid", "orders": base + "/account/1/orders"})
		return
	case "/order":
		var request struct {
			Identifiers []struct{ Type, Value string }
			Profile     string
		}
		if err := json.Unmarshal(payload, &request); err != nil || len(request.Identifiers) != 1 || request.Identifiers[0].Type != ca.kind || request.Identifiers[0].Value != ca.host || request.Profile != ca.profile {
			ca.t.Errorf("unexpected ACME order: %s (%v)", payload, err)
			http.Error(w, "invalid order", 400)
			return
		}
		ca.mu.Lock()
		ca.next++
		id := ca.next
		ca.orders[id] = &testACMEOrder{token: fmt.Sprintf("owned-challenge-token-%d", id)}
		ca.mu.Unlock()
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", base, id))
		respond(201, ca.order(id))
		return
	}
	var id int
	if _, err := fmt.Sscanf(r.URL.Path, "/authz/%d", &id); err == nil {
		ca.mu.Lock()
		o := ca.orders[id]
		status := "pending"
		if o.valid {
			status = "valid"
		}
		token := o.token
		ca.mu.Unlock()
		respond(200, map[string]any{"identifier": map[string]string{"type": ca.kind, "value": ca.host}, "status": status, "challenges": []any{map[string]any{"type": "tls-alpn-01", "url": fmt.Sprintf("%s/challenge/%d", base, id), "token": token, "status": status}}})
		return
	}
	if _, err := fmt.Sscanf(r.URL.Path, "/challenge/%d", &id); err == nil {
		ca.mu.Lock()
		o := ca.orders[id]
		token, thumb := o.token, ca.thumb
		ca.mu.Unlock()
		name := ca.host
		if ca.kind == "ip" {
			a := net.ParseIP(ca.host).To4()
			name = fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", a[3], a[2], a[1], a[0])
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ca.address, &tls.Config{ServerName: name, NextProtos: []string{acmeALPN}, InsecureSkipVerify: true}) // ACME proof is self-signed and verified below.
		if err != nil {
			ca.t.Error("TLS-ALPN validation:", err)
			http.Error(w, "proof failed", 400)
			return
		}
		state := conn.ConnectionState()
		conn.Close()
		if state.NegotiatedProtocol != acmeALPN || len(state.PeerCertificates) != 1 {
			ca.t.Error("invalid challenge negotiation")
			http.Error(w, "invalid proof", 400)
			return
		}
		leaf := state.PeerCertificates[0]
		if err = leaf.VerifyHostname(ca.host); err != nil {
			ca.t.Error(err)
			http.Error(w, "invalid SAN", 400)
			return
		}
		wanted := sha256.Sum256([]byte(token + "." + thumb))
		verified := false
		for _, ext := range leaf.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
				var digest []byte
				rest, e := asn1.Unmarshal(ext.Value, &digest)
				verified = ext.Critical && e == nil && len(rest) == 0 && bytes.Equal(digest, wanted[:])
			}
		}
		if !verified {
			ca.t.Error("ACME proof does not match the account key and token")
			http.Error(w, "bad proof", 400)
			return
		}
		ca.validations.Add(1)
		ca.mu.Lock()
		o.valid = true
		ca.mu.Unlock()
		respond(200, map[string]any{"type": "tls-alpn-01", "status": "valid", "url": fmt.Sprintf("%s/challenge/%d", base, id), "token": token})
		return
	}
	if _, err := fmt.Sscanf(r.URL.Path, "/order/%d", &id); err == nil {
		respond(200, ca.order(id))
		return
	}
	if _, err := fmt.Sscanf(r.URL.Path, "/finalize/%d", &id); err == nil {
		var request struct{ CSR string }
		_ = json.Unmarshal(payload, &request)
		der, err := base64.RawURLEncoding.DecodeString(request.CSR)
		if err != nil {
			ca.t.Error(err)
			http.Error(w, "bad CSR", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil {
			ca.t.Error("invalid CSR")
			http.Error(w, "bad CSR", 400)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(id)), DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(160 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if err = leaf.VerifyHostname(ca.host); err != nil {
			ca.t.Error(err)
			http.Error(w, "wrong CSR identity", 400)
			return
		}
		der, err = x509.CreateCertificate(rand.Reader, leaf, ca.root, csr.PublicKey, ca.key)
		if err != nil {
			ca.t.Error(err)
			http.Error(w, "signing failed", 500)
			return
		}
		cert := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.rootPEM...)
		ca.mu.Lock()
		ca.orders[id].cert = cert
		ca.mu.Unlock()
		respond(200, ca.order(id))
		return
	}
	if _, err := fmt.Sscanf(r.URL.Path, "/cert/%d", &id); err == nil {
		ca.mu.Lock()
		cert := ca.orders[id].cert
		ca.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = w.Write(cert)
		return
	}
	ca.t.Error("unexpected ACME path", r.URL.Path)
	http.NotFound(w, r)
}
func (ca *testACMECA) order(id int) map[string]any {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o := ca.orders[id]
	status := "pending"
	if o.valid {
		status = "ready"
	}
	if len(o.cert) > 0 {
		status = "valid"
	}
	value := map[string]any{"status": status, "identifiers": []any{map[string]string{"type": ca.kind, "value": ca.host}}, "authorizations": []string{fmt.Sprintf("%s/authz/%d", ca.http.URL, id)}, "finalize": fmt.Sprintf("%s/finalize/%d", ca.http.URL, id)}
	if len(o.cert) > 0 {
		value["certificate"] = fmt.Sprintf("%s/cert/%d", ca.http.URL, id)
	}
	return value
}
func useTestACMECA(s *Server, ca *testACMECA) {
	m := s.automaticTLS
	m.issuer = certmagic.NewACMEIssuer(m.config, certmagic.ACMEIssuer{CA: ca.http.URL + "/directory", Agreed: true, Profile: ca.profile, DisableHTTPChallenge: true, ListenHost: s.Config.BindHost, AltTLSALPNPort: s.listener.Addr().(*net.TCPAddr).Port, CertObtainTimeout: 10 * time.Second, Logger: zap.NewNop()})
	m.config.Issuers = []certmagic.Issuer{serverACMEIssuer{m.issuer, s.ctx}}
}

func TestAutomaticHTTPSACMEIssueRenewRestart(t *testing.T) {
	for _, host := range []string{"wwe.example.test", "203.0.113.10"} {
		t.Run(host, func(t *testing.T) {
			c := hostedConfig(t)
			c.ACMEDomain = host
			s, err := NewServer(c)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ca := newTestACMECA(t, host, s.listener.Addr().String())
			useTestACMECA(s, ca)
			done := make(chan error, 1)
			go func() { done <- s.Serve() }()
			select {
			case <-s.automaticTLS.ready:
			case <-time.After(15 * time.Second):
				t.Fatal("initial certificate not ready")
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca.rootPEM)
			check := func(s *Server) *x509.Certificate {
				t.Helper()
				tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, NextProtos: []string{"h2", "http/1.1"}}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, s.listener.Addr().String())
				}}
				defer tr.CloseIdleConnections()
				req, _ := http.NewRequest("GET", "https://"+host+"/health", nil)
				req.Header.Set("X-WWE-Lab-Key", s.key)
				res, e := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Do(req)
				if e != nil {
					t.Fatal(e)
				}
				defer res.Body.Close()
				_, _ = io.Copy(io.Discard, res.Body)
				if res.StatusCode != 200 || res.TLS.NegotiatedProtocol != "http/1.1" {
					t.Fatal("client HTTP/1.1 contract changed", res.StatusCode, res.TLS)
				}
				return res.TLS.PeerCertificates[0]
			}
			first := check(s)
			renewCtx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
			defer cancel()
			// Force the scheduled maintenance path into its renewal window,
			// avoiding a multi-day wait or a forced manual renewal API.
			s.automaticTLS.config.RenewalWindowRatio = 1
			if err = s.automaticTLS.cache.RenewManagedCertificates(renewCtx); err != nil {
				t.Fatal(err)
			}
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			renewed := false
			for !renewed {
				for _, cert := range s.automaticTLS.cache.AllMatchingCertificates(host) {
					if cert.Leaf.SerialNumber.Cmp(first.SerialNumber) != 0 {
						renewed = true
					}
				}
				if renewed {
					break
				}
				select {
				case <-renewCtx.Done():
					t.Fatal("automatic renewal did not replace cached certificate")
				case <-ticker.C:
				}
			}
			second := check(s)
			if first.SerialNumber.Cmp(second.SerialNumber) == 0 || ca.validations.Load() != 2 {
				t.Fatal("certificate was not renewed through TLS-ALPN")
			}
			key := s.key
			s.Close()
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			before := ca.requests.Load()
			restarted, err := NewServer(c)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			useTestACMECA(restarted, ca)
			// Re-open the synthetic issuer's persisted certificate without a CA call.
			if _, err = restarted.automaticTLS.config.CacheManagedCertificate(restarted.ctx, host); err != nil {
				t.Fatal(err)
			}
			restarted.automaticTLS.readyOnce.Do(func() { close(restarted.automaticTLS.ready) })
			done2 := make(chan error, 1)
			go func() { done2 <- restarted.Serve() }()
			third := check(restarted)
			if key != restarted.key || third.SerialNumber.Cmp(second.SerialNumber) != 0 || ca.requests.Load() != before {
				t.Fatal("restart lost persisted certificate/key or contacted CA")
			}
			restarted.Close()
			if err = <-done2; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestAutomaticHTTPSConstructorFailureAndSNI(t *testing.T) {
	c := hostedConfig(t)
	if err := os.MkdirAll(c.ACMECache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.ACMECache, c.ACMEDomain), []byte("invalid old PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := newAutomaticHTTPS(ctx, c, 8787, nil); err == nil {
		t.Fatal("invalid legacy PEM accepted")
	}
	if err := os.Remove(filepath.Join(c.ACMECache, c.ACMEDomain)); err != nil {
		t.Fatal(err)
	}
	c.ACMEDomain = "203.0.113.10"
	m, err := newAutomaticHTTPS(ctx, c, 8787, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	if m.issuer.Profile != "shortlived" || m.challengeName != "10.113.0.203.in-addr.arpa" || !m.issuer.DisableHTTPChallenge {
		t.Fatal("incorrect IP certificate configuration")
	}
	for _, name := range []string{"other.example.test", "203.0.113.11", "10.113.0.203.in-addr.arpa"} {
		if _, err = m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: name}); err == nil || !strings.Contains(err.Error(), "unconfigured") {
			t.Fatal("foreign SNI accepted", name, err)
		}
	}
	cancel()
	if _, err = m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled certificate wait did not stop", err)
	}
}

func TestAutomaticHTTPSShutdownDuringIssuance(t *testing.T) {
	c := hostedConfig(t)
	c.ACMEDomain = "203.0.113.10"
	s, err := NewServer(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	requested := make(chan struct{})
	var requestedOnce sync.Once
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedOnce.Do(func() { close(requested) })
		<-r.Context().Done()
	}))
	defer ca.Close()
	m := s.automaticTLS
	m.issuer = certmagic.NewACMEIssuer(m.config, certmagic.ACMEIssuer{CA: ca.URL, Agreed: true, DisableHTTPChallenge: true, ListenHost: c.BindHost, AltTLSALPNPort: s.listener.Addr().(*net.TCPAddr).Port, Logger: zap.NewNop()})
	m.config.Issuers = []certmagic.Issuer{serverACMEIssuer{m.issuer, s.ctx}}
	connected := make(chan struct{})
	var connectedOnce sync.Once
	s.http.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connectedOnce.Do(func() { close(connected) })
		}
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	select {
	case <-requested:
	case <-time.After(3 * time.Second):
		t.Fatal("initial certificate request did not start")
	}
	clientDone := make(chan error, 1)
	go func() {
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", s.listener.Addr().String(), &tls.Config{ServerName: c.ACMEDomain})
		if conn != nil {
			conn.Close()
		}
		clientDone <- e
	}()
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS client did not connect")
	}
	started := time.Now()
	s.Close()
	if time.Since(started) > 2*time.Second {
		t.Fatal("shutdown waited on the certificate authority or pending handshake")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-clientDone; err == nil {
		t.Fatal("connection succeeded without an issued certificate")
	}
}

func TestAutomaticHTTPSLegacyRSACacheName(t *testing.T) {
	c := hostedConfig(t)
	cacheHostedCertificate(t, c)
	old := filepath.Join(c.ACMECache, c.ACMEDomain)
	if err := os.Rename(old, old+"+rsa"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, err := newAutomaticHTTPS(ctx, c, 8787, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	select {
	case <-m.ready:
	default:
		t.Fatal("legacy RSA cache entry was not imported")
	}
	if _, err = os.Stat(old + "+rsa"); err != nil {
		t.Fatal("legacy file was removed", err)
	}
}
