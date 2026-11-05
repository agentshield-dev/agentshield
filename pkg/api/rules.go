package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// RuleStore is the detection rule model the rule routes serve. *state.Store
// implements it.
type RuleStore interface {
	ReadActiveDetectorRuleset(context.Context) (detector.Activation, error)
	ReadResourceRules(context.Context) ([]detector.ResourceRule, error)
	ListResourceRuleJobs(context.Context, int, string) ([]state.ResourceRuleJobSummary, error)
	ResourceRuleJobStatus(context.Context, int64) (state.ResourceRuleJobSummary, bool, error)
	ResourceRuleProposal(context.Context, int64) (json.RawMessage, bool, error)
	ReviewResourceRuleJobRules(context.Context, int64, string, string, []string) error
	RequestResourceRuleJob(context.Context, string, string) (state.ResourceRuleJobSummary, error)
}

// WithRules serves the detection rule routes from store. writable enables the
// review and regenerate routes; the API is unauthenticated, so enable it only
// on a loopback listener or behind an authenticating proxy.
func WithRules(store RuleStore, writable bool) Option {
	return func(server *Server) {
		server.rules = store
		server.rulesWritable = writable
	}
}

// ruleActor is recorded as the reviewer or requester for decisions made through
// the API. It is audit metadata, not an identity.
const ruleActor = "api/web-ui"

// draftListLimit bounds the draft list; the UI filters by resource client-side.
const draftListLimit = 500

var (
	errRulesUnavailable   = clientError("detection rule routes are not configured")
	errRuleWritesDisabled = clientError("rule review is disabled on a non-loopback listener; see --rule-review-api")
)

type rulesResponse struct {
	// Activation is null when no ruleset has been activated.
	Activation    *rulesActivation        `json:"activation"`
	Rules         []detector.Rule         `json:"rules"`
	ResourceRules []detector.ResourceRule `json:"resourceRules"`
}

type rulesActivation struct {
	Revision  uint64 `json:"revision"`
	RulesetID string `json:"rulesetId"`
}

type ruleDraftsResponse struct {
	Drafts []state.ResourceRuleJobSummary `json:"drafts"`
}

type ruleDraftResponse struct {
	Draft state.ResourceRuleJobSummary `json:"draft"`
	// Proposal is the stored proposal of a completed job, otherwise null.
	Proposal json.RawMessage `json:"proposal"`
}

type ruleReviewRequest struct {
	Decision string   `json:"decision"`
	RuleIDs  []string `json:"ruleIds,omitempty"`
}

func (server *Server) handleRules(writer http.ResponseWriter, request *http.Request) {
	if server.rules == nil {
		writeError(writer, http.StatusServiceUnavailable, "read rules", errRulesUnavailable)
		return
	}
	response := rulesResponse{Rules: []detector.Rule{}, ResourceRules: []detector.ResourceRule{}}
	activation, err := server.rules.ReadActiveDetectorRuleset(request.Context())
	switch {
	case errors.Is(err, detector.ErrNoActiveRuleset):
	case err != nil:
		writeError(writer, http.StatusInternalServerError, "read active ruleset", err)
		return
	default:
		response.Activation = &rulesActivation{Revision: activation.Revision, RulesetID: activation.Ruleset.ID}
		if activation.Ruleset.Rules != nil {
			response.Rules = activation.Ruleset.Rules
		}
	}
	resourceRules, err := server.rules.ReadResourceRules(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "read resource rules", err)
		return
	}
	if resourceRules != nil {
		response.ResourceRules = resourceRules
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) handleRuleDrafts(writer http.ResponseWriter, request *http.Request) {
	if server.rules == nil {
		writeError(writer, http.StatusServiceUnavailable, "list rule drafts", errRulesUnavailable)
		return
	}
	resourceID := request.URL.Query().Get("resourceId")
	if len(resourceID) > 128 {
		writeError(writer, http.StatusBadRequest, "list rule drafts", errors.New("resource ID must contain at most 128 bytes"))
		return
	}
	drafts, err := server.rules.ListResourceRuleJobs(request.Context(), draftListLimit, resourceID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "list rule drafts", err)
		return
	}
	if drafts == nil {
		drafts = []state.ResourceRuleJobSummary{}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, ruleDraftsResponse{Drafts: drafts})
}

func (server *Server) handleRuleDraft(writer http.ResponseWriter, request *http.Request) {
	jobID, ok := server.ruleDraftID(writer, request, "load rule draft")
	if !ok {
		return
	}
	server.writeRuleDraft(writer, request.Context(), jobID, http.StatusOK)
}

func (server *Server) handleRuleDraftReview(writer http.ResponseWriter, request *http.Request) {
	jobID, ok := server.ruleDraftID(writer, request, "review rule draft")
	if !ok {
		return
	}
	if !server.rulesWritable {
		writeError(writer, http.StatusServiceUnavailable, "review rule draft", errRuleWritesDisabled)
		return
	}
	var review ruleReviewRequest
	if err := decodeJSONRequest(writer, request, &review); err != nil {
		writeError(writer, http.StatusBadRequest, "decode rule review", err)
		return
	}
	if review.Decision != state.ResourceRuleReviewApproved && review.Decision != state.ResourceRuleReviewRejected {
		writeError(writer, http.StatusBadRequest, "review rule draft", errors.New("decision must be approved or rejected"))
		return
	}
	if err := server.rules.ReviewResourceRuleJobRules(request.Context(), jobID, review.Decision, ruleActor, review.RuleIDs); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, state.ErrResourceRuleSelectionInvalid) {
			status = http.StatusBadRequest
		} else if errors.Is(err, state.ErrResourceRuleJobNotReviewable) {
			status = http.StatusConflict
		}
		writeError(writer, status, "review rule draft", err)
		return
	}
	server.writeRuleDraft(writer, request.Context(), jobID, http.StatusOK)
}

func (server *Server) handleRuleDraftRequest(writer http.ResponseWriter, request *http.Request) {
	if server.rules == nil {
		writeError(writer, http.StatusServiceUnavailable, "regenerate rules", errRulesUnavailable)
		return
	}
	if !server.rulesWritable {
		writeError(writer, http.StatusServiceUnavailable, "regenerate rules", errRuleWritesDisabled)
		return
	}
	// The empty JSON body makes this a non-simple request, so other origins need a CORS
	// preflight that the server never grants.
	if err := decodeJSONRequest(writer, request, &struct{}{}); err != nil {
		writeError(writer, http.StatusBadRequest, "decode rule regeneration", err)
		return
	}
	resourceID := strings.TrimSpace(request.PathValue("resourceID"))
	if resourceID == "" || len(resourceID) > 128 {
		writeError(writer, http.StatusBadRequest, "regenerate rules", errors.New("resource ID must contain 1-128 bytes"))
		return
	}
	job, err := server.rules.RequestResourceRuleJob(request.Context(), resourceID, ruleActor)
	switch {
	case errors.Is(err, state.ErrResourceRuleJobInProgress):
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "regenerate rules: " + err.Error(), "draft": job})
	case errors.Is(err, state.ErrResourceRuleJobNotFound):
		writeError(writer, http.StatusNotFound, "regenerate rules", err)
	case err != nil:
		writeError(writer, http.StatusInternalServerError, "regenerate rules", err)
	default:
		writeJSON(writer, http.StatusAccepted, ruleDraftResponse{Draft: job})
	}
}

func (server *Server) ruleDraftID(writer http.ResponseWriter, request *http.Request, action string) (int64, bool) {
	if server.rules == nil {
		writeError(writer, http.StatusServiceUnavailable, action, errRulesUnavailable)
		return 0, false
	}
	jobID, err := strconv.ParseInt(request.PathValue("jobID"), 10, 64)
	if err != nil || jobID < 1 {
		writeError(writer, http.StatusBadRequest, action, errors.New("draft ID must be a positive integer"))
		return 0, false
	}
	return jobID, true
}

func (server *Server) writeRuleDraft(writer http.ResponseWriter, ctx context.Context, jobID int64, status int) {
	job, found, err := server.rules.ResourceRuleJobStatus(ctx, jobID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "load rule draft", err)
		return
	}
	if !found {
		writeError(writer, http.StatusNotFound, "load rule draft", state.ErrResourceRuleJobNotFound)
		return
	}
	response := ruleDraftResponse{Draft: job, Proposal: json.RawMessage("null")}
	if job.Status == "completed" {
		proposal, found, err := server.rules.ResourceRuleProposal(ctx, jobID)
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "load rule draft proposal", err)
			return
		}
		if found {
			response.Proposal = proposal
		}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, status, response)
}
