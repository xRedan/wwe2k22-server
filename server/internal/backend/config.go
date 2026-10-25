package backend

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const ProtocolID = "wwe2k22-lab-v2"
const TargetSHA = "cf1ed48636f425a80ceb22c64341b4e3b31c9677a4e2b1b1a08fe66c2e0e7766"
const Release = "2026.10.25-server.1"

type Config struct {
	BindHost                                                            string
	AdvertiseHost                                                       string
	HTTPHost                                                            string
	HTTPPort, UDPPort                                                   int
	AdvertiseHTTPPort, AdvertiseUDPPort                                 int
	Matchmaking, Catalog, CustomContent                                 bool
	StateFile                                                           string
	ContentQuotaMiB, MaxConnections, RoomIdleSeconds, HTTPRate, UDPRate int
	AllowedNetworks                                                     []string
	TLSCert, TLSKey, AccessKeyFile, LogFile                             string
	VerboseLog                                                          bool
	ImportImages, ImageOwner                                            string
	UpgradeImages                                                       bool
}

func DefaultConfig() Config {
	return Config{BindHost: "127.0.0.1", HTTPPort: 8787, UDPPort: 8788, ContentQuotaMiB: 256, MaxConnections: 64, RoomIdleSeconds: 3600, HTTPRate: 30, UDPRate: 2000}
}
func validIPv4(s string, bind bool) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || !a.Is4() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") || (!bind && a.IsUnspecified()) {
		return netip.Addr{}, errors.New("use a unicast IPv4 address")
	}
	return a, nil
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validHTTPHost(s string) bool {
	if _, e := validIPv4(s, false); e == nil {
		return true
	}
	if len(s) > 253 || s == "" {
		return false
	}
	onlyNumbers := true
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			onlyNumbers = false
		}
	}
	if onlyNumbers {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(s), ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func (c *Config) Validate() error {
	if _, e := validIPv4(c.BindHost, true); e != nil {
		return e
	}
	if c.AdvertiseHost == "" {
		c.AdvertiseHost = c.BindHost
	}
	if _, e := validIPv4(c.AdvertiseHost, false); e != nil {
		return e
	}
	if c.BindHost == "0.0.0.0" && len(c.AllowedNetworks) == 0 {
		return errors.New("set --allow-network when binding 0.0.0.0")
	}
	if c.HTTPHost == "" {
		c.HTTPHost = c.AdvertiseHost
	}
	if !validHTTPHost(c.HTTPHost) {
		return errors.New("invalid HTTP hostname")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("provide both TLS certificate and key")
	}
	for _, p := range []int{c.HTTPPort, c.UDPPort, c.AdvertiseHTTPPort, c.AdvertiseUDPPort} {
		if p < 0 || p > 65535 {
			return errors.New("invalid port")
		}
	}
	if c.MaxConnections < 1 || c.MaxConnections > 1024 || c.RoomIdleSeconds < 300 || c.RoomIdleSeconds > 86400 || c.ContentQuotaMiB < 1 || c.ContentQuotaMiB > 65536 {
		return errors.New("invalid resource limits")
	}
	if (c.ImportImages == "") != (c.ImageOwner == "") || c.ImportImages != "" && !c.CustomContent || c.UpgradeImages && c.ImportImages == "" {
		return errors.New("original-image import requires content, manifest and owner")
	}
	return nil
}
func readAccessKey(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() >= 128 {
		return "", errors.New("access key must be a small regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", errors.New("cannot read access key file")
	}
	defer f.Close()
	info, e = f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return "", errors.New("access key must be a regular file")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 128))
	if e != nil || len(raw) >= 128 {
		return "", errors.New("cannot read access key file")
	}

	s := strings.TrimSpace(string(raw))
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s) {
		return "", errors.New("access key must contain 64 lowercase hex characters")
	}
	return s, nil
}
func accessMatches(actual, wanted string) bool {
	return len(actual) == 64 && subtle.ConstantTimeCompare([]byte(actual), []byte(wanted)) == 1
}

var trustedCIDRs = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "26.0.0.0/8"}

type bucket struct {
	Tokens float64
	At     time.Time
}
type policyKey struct {
	IP  netip.Addr
	UDP bool
}

type networkPolicy struct {
	mu        sync.Mutex
	Networks  []netip.Prefix
	Buckets   map[policyKey]bucket
	HTTP, UDP int
	NextPrune time.Time
}

func newPolicy(c Config, key string) (*networkPolicy, error) {
	values := c.AllowedNetworks
	if values != nil && len(values) == 0 {
		return nil, errors.New("at least one allowed network is required")
	}
	if values == nil {
		values = trustedCIDRs
	}
	p := &networkPolicy{Buckets: map[policyKey]bucket{}, HTTP: c.HTTPRate, UDP: c.UDPRate}
	if p.HTTP < 1 || p.HTTP > 1000 || p.UDP < 1 || p.UDP > 50000 {
		return nil, errors.New("invalid rate")
	}
	for _, s := range values {
		net, e := netip.ParsePrefix(s)
		if e != nil || !net.Addr().Is4() || net != net.Masked() {
			return nil, errors.New("invalid IPv4 network")
		}
		trusted := false
		for _, base := range trustedCIDRs {
			b := netip.MustParsePrefix(base)
			if net.Bits() >= b.Bits() && b.Contains(net.Addr()) {
				trusted = true
			}
		}
		if !trusted && (c.TLSCert == "" || key == "") {
			return nil, errors.New("Internet-wide access requires TLS and a private access key")
		}
		p.Networks = append(p.Networks, net)
	}
	return p, nil
}
func (p *networkPolicy) admit(ip netip.Addr, channel string, now time.Time) bool {
	allowed := false
	for _, net := range p.Networks {
		if net.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	rate := p.HTTP
	if channel == "udp" {
		rate = p.UDP
	}
	key := policyKey{IP: ip, UDP: channel == "udp"}
	p.mu.Lock()
	defer p.mu.Unlock()
	b, has := p.Buckets[key]
	if !has && len(p.Buckets) >= 4096 {
		if !now.Before(p.NextPrune) {
			for k, v := range p.Buckets {
				if now.Sub(v.At) >= 120*time.Second {
					delete(p.Buckets, k)
				}
			}
			p.NextPrune = now.Add(time.Second)
		}
		if len(p.Buckets) >= 4096 {
			return false
		}
	}
	if !has {
		b = bucket{float64(rate * 2), now}
	}
	elapsed := now.Sub(b.At).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.Tokens += elapsed * float64(rate)
	if b.Tokens > float64(rate*2) {
		b.Tokens = float64(rate * 2)
	}
	ok := b.Tokens >= 1
	if ok {
		b.Tokens--
	}
	b.At = now
	p.Buckets[key] = b
	return ok
}
