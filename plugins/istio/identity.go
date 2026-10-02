package istio

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func networkDestinationClaim(networkID, host string) (graph.IdentityClaim, error) {
	networkID = strings.TrimSpace(networkID)
	canonical, _, err := canonicalHost(host)
	if err != nil {
		return graph.IdentityClaim{}, err
	}
	keyType := "dns"
	if _, err := netip.ParseAddr(canonical); err == nil {
		keyType = "ip"
	}
	return graph.NetworkDestinationClaim(networkID, keyType+"/"+canonical)
}

func canonicalHost(value string) (string, bool, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	if host == "" {
		return "", false, errors.New("host is empty")
	}
	if strings.ContainsAny(host, "/\\@?#") || strings.Contains(host, "://") {
		return "", false, errors.New("host contains URL, path, or credential syntax")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String(), false, nil
	}
	if strings.Contains(host, ":") || strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		return "", false, errors.New("host contains an embedded port or malformed IP literal")
	}
	host = strings.TrimSuffix(host, ".")
	wildcard := strings.HasPrefix(host, "*.")
	if wildcard {
		host = strings.TrimPrefix(host, "*.")
	}
	if host == "" || strings.Contains(host, "*") || len(host) > 253 {
		return "", false, errors.New("host contains a malformed wildcard or DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return "", false, fmt.Errorf("host contains invalid DNS label %q", safeLabel(label))
		}
	}
	if wildcard {
		return "*." + host, true, nil
	}
	return host, false, nil
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func safeLabel(label string) string {
	const limit = 32
	var result strings.Builder
	for _, character := range label {
		if result.Len() >= limit {
			break
		}
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' {
			result.WriteRune(character)
		} else {
			result.WriteByte('?')
		}
	}
	return result.String()
}
