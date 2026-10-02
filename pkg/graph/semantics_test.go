package graph

import "testing"

func TestSecuritySemanticsCanonicalRoundTrip(t *testing.T) {
	encoded, err := EncodeSecuritySemantics(SecuritySemantics{
		Version: SecuritySemanticsV1, Class: SecurityClassGovernance,
		Domain: SecurityDomainTransportAuthentication, State: SecurityStateDeclared,
		Effect: "require", Scope: "workload", Direction: "ingress", Coverage: "complete",
		Protocols:           []string{"TLS", "HTTP", "TLS"},
		Ports:               []SecurityPort{{Protocol: "TCP", Port: 8443}, {Protocol: "TCP", Port: 443}},
		ConfigurationDigest: "sha256:fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"v1","class":"governance","domain":"transport-authentication","state":"declared","effect":"require","scope":"workload","direction":"ingress","coverage":"complete","protocols":["HTTP","TLS"],"ports":[{"protocol":"TCP","port":443},{"protocol":"TCP","port":8443}],"configurationDigest":"sha256:fixture"}`
	if encoded != want {
		t.Fatalf("encoded semantics = %s\nwant = %s", encoded, want)
	}
	decoded, err := DecodeSecuritySemantics(map[string]string{SecuritySemanticsAttribute: encoded})
	if err != nil {
		t.Fatal(err)
	}
	if decoded == nil || decoded.Class != SecurityClassGovernance || len(decoded.Ports) != 2 {
		t.Fatalf("decoded semantics = %#v", decoded)
	}
}

func TestSecuritySemanticsRejectsEffectiveState(t *testing.T) {
	semantics := SecuritySemantics{
		Version: SecuritySemanticsV1, Class: SecurityClassGovernance, Domain: SecurityDomainAuthorization,
		State: "effective", Effect: "deny", Scope: "workload", Direction: "ingress", Coverage: "complete",
	}
	if _, err := EncodeSecuritySemantics(semantics); err == nil {
		t.Fatal("accepted effective state during encoding")
	}

	payload := `{"version":"v1","class":"governance","domain":"authorization","state":"effective","effect":"deny","scope":"workload","direction":"ingress","coverage":"complete"}`
	if _, err := DecodeSecuritySemantics(map[string]string{SecuritySemanticsAttribute: payload}); err == nil {
		t.Fatal("accepted effective state during decoding")
	}
}

func TestNetworkPeerClassIdentityUsesClosedVocabulary(t *testing.T) {
	claim, err := NetworkPeerClassClaim(" network-a ", " EXTERNAL-DESTINATION ")
	if err != nil {
		t.Fatal(err)
	}
	if claim.AuthorityID != "network-a" || claim.ImmutableKey != "external-destination" || !IsNetworkPeerClassClaim(claim) {
		t.Fatalf("unexpected normalized class claim: %#v", claim)
	}
	if _, err := NetworkPeerClassClaim("network-a", "user-defined"); err == nil {
		t.Fatal("unregistered peer class was accepted")
	}
}

func TestProcessClassIdentityUsesClosedVocabulary(t *testing.T) {
	claim, err := ProcessClassClaim(" cluster-a ", " SHELL ")
	if err != nil {
		t.Fatal(err)
	}
	if claim.AuthorityID != "cluster-a" || claim.ImmutableKey != ProcessClassShell || !IsProcessClassClaim(claim) || IsNetworkPeerClassClaim(claim) {
		t.Fatalf("unexpected normalized process class claim: %#v", claim)
	}
	if _, err := ProcessClassClaim("cluster-a", "/bin/bash"); err == nil {
		t.Fatal("unregistered process class was accepted")
	}
	if _, err := NewCompiler(NewRegistry()).Compile(Input{Resources: []ResourceAssertion{{
		Claim: claim, Kind: "process/class", PluginID: "falco", SourceID: "source", RuleID: "rule", EvidenceIDs: []string{"evidence"},
	}}}); err != nil {
		t.Fatalf("core registry rejected process class claim: %v", err)
	}
}

func TestSecuritySemanticsRejectsUnknownAndNonCanonicalPayloads(t *testing.T) {
	tests := []string{
		`{"version":"v1","class":"governance","domain":"authorization","state":"declared","effect":"allow","scope":"workload","direction":"ingress","coverage":"complete","unknown":true}`,
		`{"class":"governance","version":"v1","domain":"authorization","state":"declared","effect":"allow","scope":"workload","direction":"ingress","coverage":"complete"}`,
		`{"version":"v1","class":"governance","domain":"authorization","state":"declared","effect":"allow","scope":"workload","direction":"ingress","coverage":"complete","ports":[{"protocol":"TCP","port":0}]}`,
		`{"version":"v1","class":"governance","domain":"network-access","state":"declared","effect":"require","scope":"workload","direction":"ingress","coverage":"complete"}`,
		`{"version":"v1","class":"exposure","domain":"network-access","state":"declared","effect":"external-addressable","scope":"invented","direction":"ingress","coverage":"complete"}`,
	}
	for _, payload := range tests {
		if _, err := DecodeSecuritySemantics(map[string]string{SecuritySemanticsAttribute: payload}); err == nil {
			t.Fatalf("accepted invalid semantics: %s", payload)
		}
	}
}

func TestSecuritySemanticsBoundsCollectionsBeforeNormalization(t *testing.T) {
	protocols := make([]string, maxSecurityProtocols+1)
	for index := range protocols {
		protocols[index] = "TCP"
	}
	_, err := EncodeSecuritySemantics(SecuritySemantics{
		Version: SecuritySemanticsV1, Class: SecurityClassGovernance, Domain: SecurityDomainAuthorization,
		State: SecurityStateDeclared, Effect: "allow", Scope: "workload", Direction: "ingress", Coverage: "complete", Protocols: protocols,
	})
	if err == nil {
		t.Fatal("accepted oversized protocol input before normalization")
	}
}

func TestCompilerValidatesSecuritySemantics(t *testing.T) {
	claim, err := NetworkDestinationClaim("test", "dns/service.test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCompiler(NewRegistry()).Compile(Input{
		Resources: []ResourceAssertion{{Claim: claim, Kind: "network/destination", PluginID: "test", SourceID: "test", RuleID: "test.resource"}},
		Facets: []FacetAssertion{{
			Resource: claim, Kind: "network-exposure", Key: "test", Attributes: map[string]string{SecuritySemanticsAttribute: `{}`},
			PluginID: "test", SourceID: "test", RuleID: "test.exposure",
		}},
	})
	if err == nil {
		t.Fatal("compiler accepted invalid security semantics")
	}
}
