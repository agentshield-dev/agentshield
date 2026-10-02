package graph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const (
	// SecuritySemanticsAttribute is the facet attribute or relationship
	// property key that carries the canonical SecuritySemantics JSON.
	SecuritySemanticsAttribute = "agentshield.io/security-semantics"
	// SecuritySemanticsV1 is the only supported envelope version.
	SecuritySemanticsV1    = "v1"
	maxSecurityProtocols   = 16
	maxSecurityPorts       = 64
	maxSecurityTokenLength = 32
)

// SecurityClass separates what is reachable (exposure) from what constrains
// it (governance).
type SecurityClass string

// Security classes.
const (
	SecurityClassExposure   SecurityClass = "exposure"
	SecurityClassGovernance SecurityClass = "governance"
)

// SecurityDomain names the security mechanism a SecuritySemantics describes.
type SecurityDomain string

// Security domains.
const (
	SecurityDomainNetworkAccess           SecurityDomain = "network-access"
	SecurityDomainAuthorization           SecurityDomain = "authorization"
	SecurityDomainTransportAuthentication SecurityDomain = "transport-authentication"
)

// SecurityState records whether a security fact is declared or supported by
// provider/runtime observations. Declared configuration alone does not prove
// enforcement.
type SecurityState string

// Security states.
const (
	SecurityStateDeclared SecurityState = "declared"
	SecurityStateObserved SecurityState = "observed"
	SecurityStateUnknown  SecurityState = "unknown"
)

// SecurityPort is one protocol and port pair in a SecuritySemantics summary.
type SecurityPort struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// SecuritySemantics is the provider-neutral security meaning attached to a
// facet or relationship. Provider-native resources and attributes remain the
// provenance and drill-down surface.
type SecuritySemantics struct {
	Version             string         `json:"version"`
	Class               SecurityClass  `json:"class"`
	Domain              SecurityDomain `json:"domain"`
	State               SecurityState  `json:"state"`
	Effect              string         `json:"effect"`
	Scope               string         `json:"scope"`
	Direction           string         `json:"direction"`
	Coverage            string         `json:"coverage"`
	Protocols           []string       `json:"protocols,omitempty"`
	Ports               []SecurityPort `json:"ports,omitempty"`
	ConfigurationDigest string         `json:"configurationDigest,omitempty"`
}

// WithSecuritySemantics returns a copy of attributes with the canonical
// encoding of semantics added under SecuritySemanticsAttribute. The input map
// is not modified.
func WithSecuritySemantics(attributes map[string]string, semantics SecuritySemantics) (map[string]string, error) {
	encoded, err := EncodeSecuritySemantics(semantics)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(attributes)+1)
	for key, value := range attributes {
		result[key] = value
	}
	result[SecuritySemanticsAttribute] = encoded
	return result, nil
}

// EncodeSecuritySemantics validates semantics and returns its canonical JSON:
// protocols are trimmed, uppercased, sorted, and deduplicated, and ports are
// sorted and deduplicated. Producers must bound native input first; oversized
// protocol or port lists are rejected rather than truncated.
func EncodeSecuritySemantics(semantics SecuritySemantics) (string, error) {
	if len(semantics.Protocols) > maxSecurityProtocols || len(semantics.Ports) > maxSecurityPorts {
		return "", errors.New("security semantics exceeds protocol or port bounds")
	}
	semantics.Protocols = slices.Clone(semantics.Protocols)
	for index := range semantics.Protocols {
		semantics.Protocols[index] = strings.ToUpper(strings.TrimSpace(semantics.Protocols[index]))
	}
	slices.Sort(semantics.Protocols)
	semantics.Protocols = slices.Compact(semantics.Protocols)
	semantics.Ports = slices.Clone(semantics.Ports)
	for index := range semantics.Ports {
		semantics.Ports[index].Protocol = strings.ToUpper(strings.TrimSpace(semantics.Ports[index].Protocol))
	}
	slices.SortFunc(semantics.Ports, func(left, right SecurityPort) int {
		if comparison := strings.Compare(left.Protocol, right.Protocol); comparison != 0 {
			return comparison
		}
		return int(left.Port) - int(right.Port)
	})
	semantics.Ports = slices.Compact(semantics.Ports)
	if err := validateSecuritySemantics(semantics); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(semantics)
	if err != nil {
		return "", fmt.Errorf("encode security semantics: %w", err)
	}
	return string(encoded), nil
}

// DecodeSecuritySemantics returns the envelope stored in attributes, or nil
// when none is present. It rejects unknown fields, trailing data, invalid
// vocabulary, and any payload that differs from its canonical encoding, so the
// stored bytes, and therefore assertion content addresses, are unambiguous.
func DecodeSecuritySemantics(attributes map[string]string) (*SecuritySemantics, error) {
	payload, found := attributes[SecuritySemanticsAttribute]
	if !found {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.DisallowUnknownFields()
	var semantics SecuritySemantics
	if err := decoder.Decode(&semantics); err != nil {
		return nil, fmt.Errorf("decode security semantics: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return nil, err
	}
	canonical, err := EncodeSecuritySemantics(semantics)
	if err != nil {
		return nil, err
	}
	if canonical != payload {
		return nil, errors.New("security semantics must use canonical encoding")
	}
	return &semantics, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("security semantics contains trailing JSON")
		}
		return fmt.Errorf("decode trailing security semantics: %w", err)
	}
	return nil
}

func validateSecuritySemantics(semantics SecuritySemantics) error {
	if semantics.Version != SecuritySemanticsV1 {
		return fmt.Errorf("unsupported security semantics version %q", semantics.Version)
	}
	if semantics.Class != SecurityClassExposure && semantics.Class != SecurityClassGovernance {
		return fmt.Errorf("unsupported security semantics class %q", semantics.Class)
	}
	switch semantics.Domain {
	case SecurityDomainNetworkAccess, SecurityDomainAuthorization, SecurityDomainTransportAuthentication:
	default:
		return fmt.Errorf("unsupported security semantics domain %q", semantics.Domain)
	}
	switch semantics.State {
	case SecurityStateDeclared, SecurityStateObserved, SecurityStateUnknown:
	default:
		return fmt.Errorf("unsupported security semantics state %q", semantics.State)
	}
	if !validSecurityEffect(semantics.Class, semantics.Domain, semantics.Effect) {
		return fmt.Errorf("unsupported %s/%s security effect %q", semantics.Class, semantics.Domain, semantics.Effect)
	}
	if !oneOfSecurityToken(semantics.Scope, "workload", "namespace", "mesh", "service", "gateway", "cluster", "external", "unknown") {
		return fmt.Errorf("unsupported security semantics scope %q", semantics.Scope)
	}
	if !oneOfSecurityToken(semantics.Direction, "ingress", "egress", "bidirectional", "not-applicable", "unknown") {
		return fmt.Errorf("unsupported security semantics direction %q", semantics.Direction)
	}
	if !oneOfSecurityToken(semantics.Coverage, "complete", "partial", "unknown") {
		return fmt.Errorf("unsupported security semantics coverage %q", semantics.Coverage)
	}
	for _, protocol := range semantics.Protocols {
		if len(protocol) == 0 || len(protocol) > maxSecurityTokenLength {
			return errors.New("security semantics protocol must contain 1-32 characters")
		}
	}
	for _, port := range semantics.Ports {
		if len(port.Protocol) == 0 || len(port.Protocol) > maxSecurityTokenLength || port.Port == 0 {
			return errors.New("security semantics port requires protocol and positive port")
		}
	}
	if len(semantics.ConfigurationDigest) > 128 {
		return errors.New("security semantics configuration digest exceeds 128 characters")
	}
	return nil
}

func validSecurityEffect(class SecurityClass, domain SecurityDomain, effect string) bool {
	if effect == "unknown" {
		return true
	}
	if class == SecurityClassExposure {
		return domain == SecurityDomainNetworkAccess && oneOfSecurityToken(effect, "internal", "external-addressable")
	}
	switch domain {
	case SecurityDomainNetworkAccess:
		return oneOfSecurityToken(effect, "restrict", "allow", "deny")
	case SecurityDomainAuthorization:
		return oneOfSecurityToken(effect, "allow", "deny", "audit", "custom")
	case SecurityDomainTransportAuthentication:
		return oneOfSecurityToken(effect, "require", "permit", "disable", "inherit")
	default:
		return false
	}
}

func oneOfSecurityToken(value string, allowed ...string) bool {
	return slices.Contains(allowed, value)
}
