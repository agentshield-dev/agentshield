package telemetry

import (
	"fmt"
	"net/netip"
	"strings"
)

// Destination IP classes exposed to detector rules as destination_ip_class.
const (
	DestinationIPClassPublic  = "public"
	DestinationIPClassPrivate = "private"
	DestinationIPClassSpecial = "special"
	DestinationIPClassUnknown = "unknown"
)

// DestinationIPClassDescription pairs a destination IP class with its meaning.
type DestinationIPClassDescription struct {
	Class       string
	Description string
}

// DestinationIPClasses is the closed vocabulary of destination_ip_class, in
// a fixed order. Detector validation and the rule-authoring schema read it, so
// a class added here becomes visible to rules and models.
func DestinationIPClasses() []DestinationIPClassDescription {
	return []DestinationIPClassDescription{
		{DestinationIPClassPublic, "globally routable unicast address outside every IANA special-purpose range"},
		{DestinationIPClassPrivate, "RFC 1918 IPv4 or RFC 4193 unique-local IPv6 address"},
		{DestinationIPClassSpecial, "other non-global address, such as shared CGNAT space (100.64.0.0/10), loopback, link-local, multicast, documentation, or reserved ranges"},
		{DestinationIPClassUnknown, "no destination IP address is available"},
	}
}

// Non-global IANA special-purpose ranges not already covered by netip predicates.
var specialPurposePrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}

// ClassifyDestinationIP classifies an IP address string. An unparsable value
// returns DestinationIPClassUnknown with an error.
func ClassifyDestinationIP(raw string) (string, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return DestinationIPClassUnknown, fmt.Errorf("parse destination IP: %w", err)
	}
	return classifyAddress(address), nil
}

func classifyAddress(address netip.Addr) string {
	address = address.Unmap().WithZone("")
	if address.IsPrivate() {
		return DestinationIPClassPrivate
	}
	if !address.IsGlobalUnicast() {
		return DestinationIPClassSpecial
	}
	for _, prefix := range specialPurposePrefixes {
		if prefix.Contains(address) {
			return DestinationIPClassSpecial
		}
	}
	return DestinationIPClassPublic
}
