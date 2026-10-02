package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// preparedRemediation binds a prepared plan to the finding and proposal it was
// prepared for, so approval cannot be replayed against another finding.
type preparedRemediation struct {
	findingID    string
	proposal     remediation.Proposal
	plan         remediation.Plan
	preparation  remediation.Preparation
	result       *remediation.ExecutionResult
	verification *remediation.Verification
}

type remediationSelection struct {
	ProviderID string `json:"providerId"`
	SourceID   string `json:"sourceId"`
	ActionID   string `json:"actionId"`
}

type remediationPreparationResponse struct {
	Plan        remediation.Plan         `json:"plan"`
	Preparation *remediation.Preparation `json:"preparation,omitempty"`
}

type remediationApprovalRequest struct {
	PlanID string `json:"planId"`
}

type remediationApprovalResponse struct {
	PlanID       string                      `json:"planId"`
	Result       remediation.ExecutionResult `json:"result"`
	Verification remediation.Verification    `json:"verification"`
	// VerificationError explains an unsatisfied verification of an execution
	// that did change the provider.
	VerificationError string `json:"verificationError,omitempty"`
}

func (server *Server) handleRemediationCandidates(writer http.ResponseWriter, request *http.Request) {
	proposal, found := server.findingProposal(writer, request)
	if !found {
		return
	}
	if server.remediations == nil {
		writeError(writer, http.StatusServiceUnavailable, "enumerate remediation actions", errRemediationUnavailable)
		return
	}
	candidates, err := server.remediations.Candidates(proposal)
	if err != nil {
		writeError(writer, http.StatusConflict, "enumerate remediation actions", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"candidates": candidates})
}

// handleRemediationPrepare plans and prepares the selected action for a
// server-owned proposal. Neither step writes provider state. Advisory-only
// plans are returned without preparation and can never be approved.
func (server *Server) handleRemediationPrepare(writer http.ResponseWriter, request *http.Request) {
	proposal, found := server.findingProposal(writer, request)
	if !found {
		return
	}
	if server.remediations == nil {
		writeError(writer, http.StatusServiceUnavailable, "prepare remediation", errRemediationUnavailable)
		return
	}
	var selection remediationSelection
	if err := decodeJSONRequest(writer, request, &selection); err != nil {
		writeError(writer, http.StatusBadRequest, "decode remediation selection", err)
		return
	}
	if strings.TrimSpace(selection.ProviderID) == "" || strings.TrimSpace(selection.SourceID) == "" || strings.TrimSpace(selection.ActionID) == "" {
		writeError(writer, http.StatusBadRequest, "prepare remediation", errors.New("providerId, sourceId, and actionId are required"))
		return
	}
	plan, err := server.remediations.Plan(request.Context(), proposal, selection.ProviderID, selection.SourceID, selection.ActionID)
	if err != nil {
		writeError(writer, http.StatusConflict, "plan remediation", err)
		return
	}
	if plan.Mode == remediation.ModeAdvisoryOnly {
		writeJSON(writer, http.StatusOK, remediationPreparationResponse{Plan: plan})
		return
	}
	preparation, err := server.remediations.Prepare(request.Context(), proposal, plan)
	if err != nil {
		writeError(writer, http.StatusConflict, "prepare remediation", err)
		return
	}
	server.sessionsMu.Lock()
	server.sessions[plan.ID] = preparedRemediation{
		findingID: request.PathValue("findingID"), proposal: proposal, plan: plan, preparation: preparation,
	}
	server.sessionsMu.Unlock()
	writeJSON(writer, http.StatusOK, remediationPreparationResponse{Plan: plan, Preparation: &preparation})
}

// remediationExecutionTimeout bounds execution and verification of one
// approved plan. They run detached from the request so a client disconnect
// cannot cancel a provider write, or its rollback, halfway through.
const remediationExecutionTimeout = 2 * time.Minute

// handleRemediationApprove executes a prepared plan. The request names only the
// plan ID the user approved; the plan, preparation, and proposal come from
// server state for the same finding and proposal.
//
// Execution and verification run on a context detached from the request, so
// once approval starts, its outcome does not depend on the client staying
// connected. A successful execution is recorded on the session before
// verification. If verification then fails or is unsatisfied, the response is
// 200 with an unsatisfied verification and verificationError, because the
// provider was changed. A repeated approval never executes again: it returns
// the recorded verified result, or re-runs only verification.
func (server *Server) handleRemediationApprove(writer http.ResponseWriter, request *http.Request) {
	proposal, found := server.findingProposal(writer, request)
	if !found {
		return
	}
	if server.remediations == nil {
		writeError(writer, http.StatusServiceUnavailable, "approve remediation", errRemediationUnavailable)
		return
	}
	var approval remediationApprovalRequest
	if err := decodeJSONRequest(writer, request, &approval); err != nil {
		writeError(writer, http.StatusBadRequest, "decode remediation approval", err)
		return
	}
	server.sessionsMu.Lock()
	session, ok := server.sessions[approval.PlanID]
	server.sessionsMu.Unlock()
	if !ok || approval.PlanID != session.plan.ID || session.findingID != request.PathValue("findingID") || session.proposal.ID != proposal.ID {
		writeError(writer, http.StatusConflict, "approve remediation", errors.New("matching prepared remediation was not found"))
		return
	}
	if session.result != nil && session.verification != nil && session.verification.Satisfied {
		writeJSON(writer, http.StatusOK, remediationApprovalResponse{PlanID: session.plan.ID, Result: *session.result, Verification: *session.verification})
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), remediationExecutionTimeout)
	defer cancel()
	if session.result == nil {
		result, err := server.remediations.Execute(ctx, proposal, session.plan, session.preparation, approval.PlanID)
		if err != nil {
			writeError(writer, http.StatusConflict, "execute remediation", err)
			return
		}
		session.result = &result
		server.recordRemediation(session)
		slog.Info("remediation executed", "findingID", session.findingID, "planID", session.plan.ID,
			"providerID", session.plan.ProviderID, "sourceID", session.plan.SourceID, "actionID", session.plan.ActionID, "resultID", result.ID)
	}
	result := *session.result
	verification, err := server.remediations.Verify(ctx, proposal, session.plan)
	response := remediationApprovalResponse{PlanID: session.plan.ID, Result: result, Verification: verification}
	switch {
	case err != nil:
		response.Verification = unsatisfiedVerification(session.plan, result)
		response.VerificationError = "verify remediation: " + err.Error()
	case !verification.Satisfied:
		response.VerificationError = "verify remediation: provider declaration was not satisfied"
	}
	session.verification = &response.Verification
	server.recordRemediation(session)
	if response.VerificationError != "" {
		slog.Warn("remediation executed but not verified", "findingID", session.findingID, "planID", session.plan.ID,
			"providerID", session.plan.ProviderID, "resultID", result.ID, "error", response.VerificationError)
	}
	writeJSON(writer, http.StatusOK, response)
}

// recordRemediation stores session's execution outcome. Sessions live in
// memory only; see docs/architecture/remediation.md.
func (server *Server) recordRemediation(session preparedRemediation) {
	server.sessionsMu.Lock()
	server.sessions[session.plan.ID] = session
	server.sessionsMu.Unlock()
}

func unsatisfiedVerification(plan remediation.Plan, result remediation.ExecutionResult) remediation.Verification {
	return remediation.Verification{
		PlanID: plan.ID, ProviderID: plan.ProviderID, SourceID: plan.SourceID, ActionID: plan.ActionID, ExecutionResultID: result.ID,
	}
}

// findingProposal loads a proposal from a stored, active finding. Proposals
// are never accepted from the request.
func (server *Server) findingProposal(writer http.ResponseWriter, request *http.Request) (remediation.Proposal, bool) {
	finding, err := server.store.GetFinding(request.Context(), request.PathValue("findingID"))
	if err != nil {
		writeFindingError(writer, "load finding", err)
		return remediation.Proposal{}, false
	}
	if finding.Status != state.FindingStatusActive {
		writeError(writer, http.StatusConflict, "load finding remediation", errors.New("finding is no longer active"))
		return remediation.Proposal{}, false
	}
	proposalID := request.PathValue("proposalID")
	for _, proposal := range finding.Remediations {
		if proposal.ID == proposalID {
			return proposal, true
		}
	}
	writeError(writer, http.StatusNotFound, "load finding remediation", fmt.Errorf("proposal %q was not found on finding", proposalID))
	return remediation.Proposal{}, false
}

// decodeJSONRequest strictly decodes one bounded JSON object.
//
// Requiring Content-Type application/json is the CSRF defense for the
// unauthenticated loopback API: browsers send cross-origin form posts and
// simple fetches only with form or text content types, and an
// application/json request from another origin needs a CORS preflight that
// this server never approves. DNS rebinding bypasses this by making the
// attacker same-origin; [WithLoopbackHostCheck] covers that case.
func decodeJSONRequest(writer http.ResponseWriter, request *http.Request, target any) error {
	if contentType := request.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 64*1024)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func writeFindingError(writer http.ResponseWriter, action string, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, state.ErrFindingNotFound) {
		status = http.StatusNotFound
	}
	writeError(writer, status, action, err)
}
