package backend

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPublicAddressLiteralAndDNS(t *testing.T) {
	for _, host := range []string{"203.0.113.10", "WWE.EXAMPLE.TEST"} {
		t.Run(host, func(t *testing.T) {
			c := hostedConfig(t)
			c.ACMEDomain = ""
			c.PublicAddress = host
			calls := 0
			err := c.resolvePublicAddress(context.Background(), func(ctx context.Context, network, name string) ([]netip.Addr, error) {
				calls++
				if network != "ip4" || name != "wwe.example.test" {
					t.Fatal(network, name)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("unbounded DNS")
				}
				return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.10")}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if c.AdvertiseHost != "203.0.113.10" || c.HTTPHost != c.PublicAddress || c.ACMEDomain != c.PublicAddress {
				t.Fatal(c)
			}
			if host == "203.0.113.10" && calls != 0 || host != "203.0.113.10" && calls != 1 {
				t.Fatal("unexpected lookup count", calls)
			}
			if err = c.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPublicAddressRejectsInvalidInput(t *testing.T) {
	for _, host := range []string{"https://example.com", "example.com:443", "example.com/path", "*.example.com", "localhost", "wwe.local", "wwe.internal", "wwe.home.arpa", "127.0.0.1", "10.0.0.1", "192.168.1.1", "100.64.0.1", "0.1.0.1", "240.1.0.1", "224.0.0.1", "::1", "2001:db8::1", "999.0.0.1", " example.com", "example.com.", "example.com\x00"} {
		t.Run(host, func(t *testing.T) {
			c := DefaultConfig()
			c.PublicAddress = host
			if c.normalizePublicAddress() == nil {
				t.Fatal("invalid address accepted")
			}
		})
	}
}
func TestPublicAddressDNSFailureAndOverride(t *testing.T) {
	for _, addresses := range [][]netip.Addr{nil, {netip.MustParseAddr("10.0.0.1")}, {netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")}} {
		c := DefaultConfig()
		c.PublicAddress = "wwe.example.test"
		if c.resolvePublicAddress(context.Background(), func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }) == nil {
			t.Fatal("ambiguous DNS accepted")
		}
	}
	c := DefaultConfig()
	c.PublicAddress = "wwe.example.test"
	if c.resolvePublicAddress(context.Background(), func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("private DNS failure details")
	}) == nil {
		t.Fatal("DNS failure ignored")
	}
	c.AdvertiseHost = "203.0.113.42"
	if err := c.resolvePublicAddress(context.Background(), func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("explicit relay override resolved")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	c.HTTPHost = "other.example.test"
	if c.normalizePublicAddress() == nil {
		t.Fatal("conflicting HTTP address accepted")
	}
}
