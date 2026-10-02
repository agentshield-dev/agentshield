package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/state"
)

type findingCursor struct {
	CreatedAt time.Time `json:"createdAt"`
	ID        string    `json:"id"`
}

type findingsResponse struct {
	Findings   []state.Finding `json:"findings"`
	NextCursor string          `json:"nextCursor,omitempty"`
	Total      int             `json:"total"`
}

func (server *Server) handleFindings(writer http.ResponseWriter, request *http.Request) {
	query, err := parseFindingQuery(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "query findings", err)
		return
	}
	page, err := server.store.QueryFindings(request.Context(), query)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query findings", err)
		return
	}
	response := findingsResponse{Findings: page.Findings, Total: page.Total}
	if page.HasMore && len(page.Findings) > 0 {
		last := page.Findings[len(page.Findings)-1]
		response.NextCursor, err = encodeFindingCursor(findingCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "encode finding cursor", err)
			return
		}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) handleFinding(writer http.ResponseWriter, request *http.Request) {
	finding, err := server.store.GetFinding(request.Context(), request.PathValue("findingID"))
	if err != nil {
		writeFindingError(writer, "load finding", err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, finding)
}

func parseFindingQuery(request *http.Request) (state.FindingQuery, error) {
	values := request.URL.Query()
	query := state.FindingQuery{
		Status: values.Get("status"), Severity: values.Get("severity"), Category: values.Get("category"),
		AffectedEntityID: values.Get("affectedEntityId"), Limit: 50,
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil {
			return state.FindingQuery{}, errors.New("finding limit must be an integer")
		}
		query.Limit = limit
	}
	if value := values.Get("cursor"); value != "" {
		cursor, err := decodeFindingCursor(value)
		if err != nil {
			return state.FindingQuery{}, err
		}
		query.BeforeCreatedAt = &cursor.CreatedAt
		query.BeforeFindingID = cursor.ID
	}
	if err := query.Validate(); err != nil {
		return state.FindingQuery{}, err
	}
	return query, nil
}

func encodeFindingCursor(cursor findingCursor) (string, error) {
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeFindingCursor(value string) (findingCursor, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return findingCursor{}, errors.New("finding cursor is invalid")
	}
	var cursor findingCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.CreatedAt.IsZero() || strings.TrimSpace(cursor.ID) == "" {
		return findingCursor{}, errors.New("finding cursor is invalid")
	}
	return cursor, nil
}
