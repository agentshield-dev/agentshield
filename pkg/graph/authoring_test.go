package graph

import (
	"strings"
	"testing"
)

func TestResourceAuthoringContextRejectsUnsafeShapeAndCanonicalizesDigest(t *testing.T) {
	left, err := DecodeResourceAuthoringContext(`{"schemaVersion":"v1","context":{"name":"binding","roles":["admin"]},"attributes":{"roleClass":"admin"}}`)
	if err != nil {
		t.Fatal(err)
	}
	right, err := DecodeResourceAuthoringContext(`{ "attributes": { "roleClass": "admin" }, "context": { "roles": [ "admin" ], "name": "binding" }, "schemaVersion": "v1" }`)
	if err != nil {
		t.Fatal(err)
	}
	leftDigest, _ := left.SHA256()
	rightDigest, _ := right.SHA256()
	if leftDigest != rightDigest {
		t.Fatalf("equivalent contexts produced %q and %q", leftDigest, rightDigest)
	}
	right.SourceRevisionSHA256 = strings.Repeat("a", 64)
	revisedDigest, err := right.SHA256()
	if err != nil || revisedDigest == leftDigest {
		t.Fatalf("source revision digest=%q original=%q err=%v", revisedDigest, leftDigest, err)
	}
	for _, encoded := range []string{
		`{"schemaVersion":"v1","context":[]}`,
		`{"schemaVersion":"v1","context":{},"manifest":{}}`,
		`{"schemaVersion":"v1","sourceRevisionSha256":"abc","context":{}}`,
		`{"schemaVersion":"v1","context":{},"attributes":{"roleClass":"` + strings.Repeat("x", 2049) + `"}}`,
	} {
		if _, err := DecodeResourceAuthoringContext(encoded); err == nil {
			t.Fatalf("accepted invalid context %.80q", encoded)
		}
	}
}
