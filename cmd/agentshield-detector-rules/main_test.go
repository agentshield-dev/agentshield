package main

import (
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/rulescli"
)

func TestDecodeRuleset(t *testing.T) {
	for _, input := range []string{`{"id":"test","rules":[]}`, `{"id":"test"}`} {
		if _, err := rulescli.DecodeRuleset(strings.NewReader(input)); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{`{"id":"test","unexpected":true}`, `{"id":"test"} {}`, `{"rules":[{"unexpected":true}]}`, `not JSON`} {
		if _, err := rulescli.DecodeRuleset(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
