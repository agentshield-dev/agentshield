package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

type graphCounts struct {
	Resources     int `json:"resources"`
	Relationships int `json:"relationships"`
	Facets        int `json:"facets"`
	Telemetry     int `json:"telemetry"`
	ExposureFacts int `json:"exposureFacts"`
}

type overviewResponse struct {
	GraphSHA256           string              `json:"graphSha256"`
	GeneratedAt           time.Time           `json:"generatedAt"`
	Counts                graphCounts         `json:"counts"`
	Manifest              state.GraphManifest `json:"manifest"`
	ActiveFindings        []state.Finding     `json:"activeFindings"`
	ActiveFindingsHasMore bool                `json:"activeFindingsHasMore"`
}

type resourcesResponse struct {
	GraphSHA256 string           `json:"graphSha256"`
	Resources   []graph.Resource `json:"resources"`
	NextCursor  string           `json:"nextCursor,omitempty"`
}

type relationshipsResponse struct {
	GraphSHA256   string               `json:"graphSha256"`
	Relationships []graph.Relationship `json:"relationships"`
	NextCursor    string               `json:"nextCursor,omitempty"`
}

type resourceResponse struct {
	GraphSHA256     string               `json:"graphSha256"`
	Resource        graph.Resource       `json:"resource"`
	Relationships   []graph.Relationship `json:"relationships"`
	Facets          []graph.Facet        `json:"facets"`
	Findings        []state.Finding      `json:"findings"`
	FindingsHasMore bool                 `json:"findingsHasMore"`
}

type relationshipResponse struct {
	GraphSHA256  string             `json:"graphSha256"`
	Relationship graph.Relationship `json:"relationship"`
	Subject      graph.Resource     `json:"subject"`
	Object       graph.Resource     `json:"object"`
}

type exposureFact struct {
	ID          string                  `json:"id"`
	OwnerType   string                  `json:"ownerType"`
	OwnerID     string                  `json:"ownerId"`
	ResourceID  string                  `json:"resourceId,omitempty"`
	SubjectID   string                  `json:"subjectId,omitempty"`
	ObjectID    string                  `json:"objectId,omitempty"`
	Semantics   graph.SecuritySemantics `json:"semantics"`
	PluginID    string                  `json:"pluginId"`
	SourceID    string                  `json:"sourceId"`
	RuleID      string                  `json:"ruleId"`
	EvidenceIDs []string                `json:"evidenceIds"`
}

type exposuresResponse struct {
	GraphSHA256 string         `json:"graphSha256"`
	Exposures   []exposureFact `json:"exposures"`
	NextCursor  string         `json:"nextCursor,omitempty"`
}

func (server *Server) handleOverview(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	record, err := server.store.CurrentGraph(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "load graph overview", err)
		return
	}
	manifest, err := server.createManifest(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "create graph manifest", err)
		return
	}
	findings, err := server.store.QueryFindings(request.Context(), state.FindingQuery{Status: state.FindingStatusActive, Limit: 5})
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query priority findings", err)
		return
	}
	exposures, err := collectExposureFacts(record.Snapshot)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "decode exposure facts", err)
		return
	}
	writeJSON(writer, http.StatusOK, overviewResponse{
		GraphSHA256: record.SHA256, GeneratedAt: record.GeneratedAt,
		Counts:   graphCounts{Resources: len(record.Snapshot.Resources), Relationships: len(record.Snapshot.Relationships), Facets: len(record.Snapshot.Facets), Telemetry: len(record.Snapshot.Telemetry), ExposureFacts: len(exposures)},
		Manifest: manifest, ActiveFindings: findings.Findings, ActiveFindingsHasMore: findings.HasMore,
	})
}

func (server *Server) handleResources(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	limit, after, err := pageQuery(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "query resources", err)
		return
	}
	page, err := server.store.QueryResources(request.Context(), state.ResourceQuery{
		Search: request.URL.Query().Get("q"), Kind: strings.TrimSpace(request.URL.Query().Get("kind")),
		Namespace: strings.TrimSpace(request.URL.Query().Get("namespace")), After: after, Limit: limit,
	})
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "load resources", err)
		return
	}
	writeJSON(writer, http.StatusOK, resourcesResponse{GraphSHA256: page.GraphSHA256, Resources: page.Resources, NextCursor: encodeCursor(page.Next)})
}

func (server *Server) handleResource(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	detail, err := server.store.GetResourceDetail(request.Context(), request.PathValue("resourceID"))
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, state.ErrGraphEntityNotFound) {
			status = http.StatusNotFound
		}
		writeError(writer, status, "load resource", err)
		return
	}
	findings, err := server.store.QueryFindings(request.Context(), state.FindingQuery{AffectedEntityID: detail.Resource.ID, Limit: 100})
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query resource findings", err)
		return
	}
	writeJSON(writer, http.StatusOK, resourceResponse{GraphSHA256: detail.GraphSHA256, Resource: detail.Resource, Relationships: detail.Relationships, Facets: detail.Facets, Findings: findings.Findings, FindingsHasMore: findings.HasMore})
}

func (server *Server) handleRelationships(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	limit, after, err := pageQuery(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "query relationships", err)
		return
	}
	page, err := server.store.QueryRelationships(request.Context(), state.RelationshipQuery{
		Search: request.URL.Query().Get("q"), Predicate: strings.TrimSpace(request.URL.Query().Get("predicate")),
		ResourceID: strings.TrimSpace(request.URL.Query().Get("resourceId")), After: after, Limit: limit,
	})
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "load relationships", err)
		return
	}
	writeJSON(writer, http.StatusOK, relationshipsResponse{GraphSHA256: page.GraphSHA256, Relationships: page.Relationships, NextCursor: encodeCursor(page.Next)})
}

func (server *Server) handleRelationship(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	detail, err := server.store.GetRelationshipDetail(request.Context(), request.PathValue("relationshipID"))
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, state.ErrGraphEntityNotFound) {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "unresolved") {
			status = http.StatusConflict
		}
		writeError(writer, status, "load relationship", err)
		return
	}
	writeJSON(writer, http.StatusOK, relationshipResponse{GraphSHA256: detail.GraphSHA256, Relationship: detail.Relationship, Subject: detail.Subject, Object: detail.Object})
}

func (server *Server) handleExposures(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	record, err := server.store.CurrentGraph(request.Context())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "load exposure facts", err)
		return
	}
	facts, err := collectExposureFacts(record.Snapshot)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "decode exposure facts", err)
		return
	}
	stateFilter := strings.TrimSpace(request.URL.Query().Get("state"))
	coverage := strings.TrimSpace(request.URL.Query().Get("coverage"))
	resourceID := strings.TrimSpace(request.URL.Query().Get("resourceId"))
	if stateFilter != "" && !slices.Contains([]string{string(graph.SecurityStateDeclared), string(graph.SecurityStateObserved), string(graph.SecurityStateUnknown)}, stateFilter) {
		writeError(writer, http.StatusBadRequest, "query exposure facts", errors.New("exposure state is invalid"))
		return
	}
	if coverage != "" && !slices.Contains([]string{"complete", "partial", "unknown"}, coverage) {
		writeError(writer, http.StatusBadRequest, "query exposure facts", errors.New("exposure coverage is invalid"))
		return
	}
	facts = slices.DeleteFunc(facts, func(fact exposureFact) bool {
		if stateFilter != "" && string(fact.Semantics.State) != stateFilter || coverage != "" && fact.Semantics.Coverage != coverage {
			return true
		}
		return resourceID != "" && fact.ResourceID != resourceID && fact.SubjectID != resourceID && fact.ObjectID != resourceID
	})
	page, next, err := paginate(facts, request, func(item exposureFact) string { return item.ID })
	if err != nil {
		writeError(writer, http.StatusBadRequest, "query exposure facts", err)
		return
	}
	writeJSON(writer, http.StatusOK, exposuresResponse{GraphSHA256: record.SHA256, Exposures: page, NextCursor: next})
}

func collectExposureFacts(snapshot graph.Snapshot) ([]exposureFact, error) {
	facts := make([]exposureFact, 0)
	for _, relationship := range snapshot.Relationships {
		for index, assertion := range relationship.Assertions {
			semantics, err := graph.DecodeSecuritySemantics(assertion.Properties)
			if err != nil {
				return nil, err
			}
			if semantics != nil && semantics.Class == graph.SecurityClassExposure {
				facts = append(facts, exposureFact{ID: relationship.ID + ":" + strconv.Itoa(index), OwnerType: "relationship", OwnerID: relationship.ID, SubjectID: relationship.SubjectID, ObjectID: relationship.ObjectID, Semantics: *semantics, PluginID: assertion.PluginID, SourceID: assertion.SourceID, RuleID: assertion.RuleID, EvidenceIDs: assertion.EvidenceIDs})
			}
		}
	}
	for _, facet := range snapshot.Facets {
		for index, assertion := range facet.Assertions {
			semantics, err := graph.DecodeSecuritySemantics(assertion.Attributes)
			if err != nil {
				return nil, err
			}
			if semantics != nil && semantics.Class == graph.SecurityClassExposure {
				facts = append(facts, exposureFact{ID: facet.ID + ":" + strconv.Itoa(index), OwnerType: "facet", OwnerID: facet.ID, ResourceID: facet.ResourceID, Semantics: *semantics, PluginID: assertion.PluginID, SourceID: assertion.SourceID, RuleID: assertion.RuleID, EvidenceIDs: assertion.EvidenceIDs})
			}
		}
	}
	slices.SortFunc(facts, func(left, right exposureFact) int { return strings.Compare(left.ID, right.ID) })
	return facts, nil
}

func pageQuery(request *http.Request) (int, string, error) {
	limit := 25
	if value := request.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, "", errors.New("limit must be between 1 and 100")
		}
		limit = parsed
	}
	after := ""
	if value := request.URL.Query().Get("cursor"); value != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) == 0 {
			return 0, "", errors.New("cursor is invalid")
		}
		after = string(decoded)
	}
	return limit, after, nil
}

func encodeCursor(value string) string {
	if value == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func paginate[T any](items []T, request *http.Request, id func(T) string) ([]T, string, error) {
	limit := 25
	if value := request.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			return nil, "", errors.New("limit must be between 1 and 100")
		}
		limit = parsed
	}
	after := ""
	if value := request.URL.Query().Get("cursor"); value != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) == 0 {
			return nil, "", errors.New("cursor is invalid")
		}
		after = string(decoded)
	}
	start := 0
	if after != "" {
		start = len(items)
		for index, item := range items {
			if id(item) > after {
				start = index
				break
			}
		}
	}
	end := min(len(items), start+limit)
	next := ""
	if end < len(items) {
		next = base64.RawURLEncoding.EncodeToString([]byte(id(items[end-1])))
	}
	return items[start:end], next, nil
}

func findResource(resources []graph.Resource, id string) (graph.Resource, bool) {
	for _, resource := range resources {
		if resource.ID == id {
			return resource, true
		}
	}
	return graph.Resource{}, false
}

func resourceDisplayName(resource graph.Resource) string {
	for _, assertion := range resource.Assertions {
		if assertion.DisplayName != "" {
			return assertion.DisplayName
		}
	}
	return resource.Identity.ImmutableKey
}

func resourceNamespace(resource graph.Resource) string {
	for _, assertion := range resource.Assertions {
		for _, key := range []string{"namespace", "kubernetes/namespace", "istio/namespace"} {
			if namespace := assertion.Attributes[key]; namespace != "" {
				return namespace
			}
		}
	}
	return ""
}

func resourceSearchText(resource graph.Resource) string {
	parts := []string{resource.ID, resource.Kind, resourceDisplayName(resource), resourceNamespace(resource), resource.Identity.AuthorityID, resource.Identity.ImmutableKey}
	for _, assertion := range resource.Assertions {
		parts = append(parts, assertion.PluginID, assertion.SourceID, assertion.RuleID)
		for key, value := range assertion.Attributes {
			parts = append(parts, key, value)
		}
	}
	return strings.Join(parts, " ")
}
