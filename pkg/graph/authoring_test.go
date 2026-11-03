package graph

import (
	"strings"
	"testing"
)

func TestResourceAuthoringProjectionRejectsUnsafeShapeAndCanonicalizesRevision(t *testing.T) {
	left, err := DecodeResourceAuthoringProjection(`{"schemaVersion":"v1","context":{"name":"binding","roles":["admin"]},"attributes":{"roleClass":"admin"}}`)
	if err != nil {
		t.Fatal(err)
	}
	right, err := DecodeResourceAuthoringProjection(`{ "attributes": { "roleClass": "admin" }, "context": { "roles": [ "admin" ], "name": "binding" }, "schemaVersion": "v1" }`)
	if err != nil {
		t.Fatal(err)
	}
	leftRevision, _ := left.RevisionSHA256()
	rightRevision, _ := right.RevisionSHA256()
	if leftRevision != rightRevision {
		t.Fatalf("equivalent projections produced %q and %q", leftRevision, rightRevision)
	}
	for _, encoded := range []string{
		`{"schemaVersion":"v1","context":[]}`,
		`{"schemaVersion":"v1","context":{},"manifest":{}}`,
		`{"schemaVersion":"v1","context":{},"attributes":{"roleClass":"` + strings.Repeat("x", 2049) + `"}}`,
	} {
		if _, err := DecodeResourceAuthoringProjection(encoded); err == nil {
			t.Fatalf("accepted invalid projection %.80q", encoded)
		}
	}
}
