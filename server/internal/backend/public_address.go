package backend

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
)

func validAutomaticSubject(host string) bool {
	if !validHTTPHost(host) {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && ip.As4()[0] > 0 && ip.As4()[0] < 224 && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
	}
	return strings.Contains(host, ".") && !strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal") && !strings.HasSuffix(host, ".home.arpa")
}

func (c *Config) normalizePublicAddress() error {
	if c.PublicAddress == "" {
		return nil
	}
	address := strings.ToLower(c.PublicAddress)
	if !validAutomaticSubject(address) {
		return errors.New("public-address must be a public IPv4 or DNS hostname without scheme, port or path")
	}
	if c.HTTPHost != "" && !strings.EqualFold(c.HTTPHost, address) || c.ACMEDomain != "" && !strings.EqualFold(c.ACMEDomain, address) {
		return errors.New("public-address conflicts with http-host or acme-domain")
	}
	c.PublicAddress, c.HTTPHost, c.ACMEDomain = address, address, address
	if ip, err := netip.ParseAddr(address); err == nil && c.AdvertiseHost == "" {
		c.AdvertiseHost = ip.String()
	}
	return nil
}

type ipv4Lookup func(context.Context, string, string) ([]netip.Addr, error)

// DNS is resolved once for the UDP relay. Multiple IPv4 destinations require
// an explicit advertise-host rather than choosing a potentially wrong server.
func (c *Config) resolvePublicAddress(ctx context.Context, lookup ipv4Lookup) error {
	if err := c.normalizePublicAddress(); err != nil {
		return err
	}
	if c.PublicAddress == "" || c.AdvertiseHost != "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := lookup(ctx, "ip4", c.PublicAddress)
	if err != nil {
		return errors.New("cannot resolve public-address to IPv4; check DNS or set advertise-host")
	}
	unique := map[netip.Addr]bool{}
	for _, ip := range addresses {
		ip = ip.Unmap()
		if ip.Is4() && validAutomaticSubject(ip.String()) {
			unique[ip] = true
		}
	}
	if len(unique) != 1 {
		return errors.New("public-address must resolve to one public IPv4; set advertise-host explicitly for multiple records")
	}
	for ip := range unique {
		c.AdvertiseHost = ip.String()
	}
	return nil
}
