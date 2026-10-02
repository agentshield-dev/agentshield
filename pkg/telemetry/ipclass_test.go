package telemetry

import "testing"

func TestClassifyDestinationIP(t *testing.T) {
	for raw, want := range map[string]string{
		"8.8.8.8": DestinationIPClassPublic, "172.32.0.1": DestinationIPClassPublic, "2606:4700::1111": DestinationIPClassPublic,
		"10.1.2.3": DestinationIPClassPrivate, "172.16.0.1": DestinationIPClassPrivate, "192.168.1.1": DestinationIPClassPrivate, "fd00::1": DestinationIPClassPrivate,
		"100.64.0.1": DestinationIPClassSpecial, "127.0.0.1": DestinationIPClassSpecial, "169.254.169.254": DestinationIPClassSpecial,
		"203.0.113.5": DestinationIPClassSpecial, "198.18.0.1": DestinationIPClassSpecial, "224.0.0.1": DestinationIPClassSpecial,
		"255.255.255.255": DestinationIPClassSpecial, "2001:db8::1": DestinationIPClassSpecial, "fe80::1": DestinationIPClassSpecial, "::1": DestinationIPClassSpecial,
		"::ffff:8.8.8.8": DestinationIPClassPublic, "::ffff:10.0.0.1": DestinationIPClassPrivate,
	} {
		if got, err := ClassifyDestinationIP(raw); err != nil || got != want {
			t.Errorf("%s: class=%q err=%v, want %q", raw, got, err, want)
		}
	}
	if got, err := ClassifyDestinationIP("not-an-ip"); err == nil || got != DestinationIPClassUnknown {
		t.Fatalf("invalid address: class=%q err=%v", got, err)
	}
}

func TestNetworkPeerClassUsesSharedIPClassification(t *testing.T) {
	for key, want := range map[string]string{
		"ip/8.8.8.8": "external-destination", "ip/10.0.0.1": "private-ip", "ip/::ffff:10.0.0.1": "private-ip",
		"ip/127.0.0.1": "loopback-ip", "ip/169.254.169.254": "link-local-ip",
		"ip/100.64.0.1": "special-use-ip", "ip/203.0.113.5": "special-use-ip", "ip/2001:db8::1": "special-use-ip",
		"dns/example.com": "dns-destination",
	} {
		if got := networkPeerClass(key, false); got != want {
			t.Errorf("%s: class=%q, want %q", key, got, want)
		}
	}
}
