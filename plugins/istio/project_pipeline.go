package istio

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// ProjectObserved deterministically projects one coherent snapshot. The
// result is independent of observation order.
func ProjectObserved(scope ProjectionContext, observations []ObservedObject) (ProjectionResult, error) {
	scope.ClusterID = strings.TrimSpace(scope.ClusterID)
	scope.NetworkID = strings.TrimSpace(scope.NetworkID)
	if scope.NetworkID == "" {
		scope.NetworkID = scope.ClusterID
	}
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	scope.RootNamespace = strings.TrimSpace(scope.RootNamespace)
	if scope.RootNamespace == "" {
		scope.RootNamespace = "istio-system"
	}
	if scope.ClusterID == "" || scope.SourceID == "" {
		return ProjectionResult{}, errors.New("cluster and source IDs are required")
	}
	projector := &projection{context: scope}
	projector.index = NewIndex(scope, observations)
	if err := projector.projectServiceEntries(); err != nil {
		return ProjectionResult{}, err
	}
	if err := projector.projectVirtualServices(); err != nil {
		return ProjectionResult{}, err
	}
	if err := projector.projectAuthorizationPolicies(); err != nil {
		return ProjectionResult{}, err
	}
	if err := projector.projectPeerAuthentications(); err != nil {
		return ProjectionResult{}, err
	}
	if err := projector.projectAmbientAndWaypoints(); err != nil {
		return ProjectionResult{}, err
	}
	projector.sortOutput()
	return ProjectionResult{Input: projector.input, Diagnostics: projector.diagnostics}, nil
}

func (projector *projection) sortOutput() {
	slices.SortFunc(projector.input.Resources, func(left, right graph.ResourceAssertion) int {
		return cmp.Compare(claimKey(left.Claim)+left.Kind+left.RuleID, claimKey(right.Claim)+right.Kind+right.RuleID)
	})
	slices.SortFunc(projector.input.Facets, func(left, right graph.FacetAssertion) int {
		return cmp.Compare(claimKey(left.Resource)+left.Kind+left.Key, claimKey(right.Resource)+right.Kind+right.Key)
	})
	slices.SortFunc(projector.input.Relationships, func(left, right graph.RelationshipAssertion) int {
		return cmp.Compare(claimKey(left.Subject)+string(left.Predicate)+claimKey(left.Object)+left.Qualifier, claimKey(right.Subject)+string(right.Predicate)+claimKey(right.Object)+right.Qualifier)
	})
	slices.SortFunc(projector.diagnostics, func(left, right Diagnostic) int {
		return cmp.Compare(left.Resource+left.Code, right.Resource+right.Code)
	})
}

func claimKey(claim graph.IdentityClaim) string {
	return strings.Join([]string{
		claim.Scheme.Group,
		claim.Scheme.Version,
		claim.Scheme.Kind,
		claim.AuthorityID,
		claim.ImmutableKey,
	}, "\x00")
}
