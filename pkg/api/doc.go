// Package api serves the AgentShield HTTP API, the embedded web UI, and the
// optional OTLP log receiver.
//
// The API is a read model over pkg/state: graph, catalog, and finding routes
// query the current materialized graph and stored findings and never modify
// the graph. The only routes that can change anything outside AgentShield are
// the remediation routes. They are always registered but act only on a server
// built with [NewServerWithRemediations]; otherwise they return 503.
//
// The rule review and regenerate routes change detection: approving a draft
// makes its rules active, and regenerating resets a Deployment's draft to
// shadow mode and calls the model again. They are always registered but act
// only on a server built with [WithRules] and writes enabled; otherwise they
// return 503. Enable writes only on a loopback listener or behind an
// authenticating proxy.
//
// The manifest and overview routes do write: they call
// [state.Store.CreateManifest], which records the active contribution versions
// as a content-addressed manifest row, the same record analysis views pin. The
// row supplies the response's stable creation time and parent link, so
// computing the manifest without storing it would change what clients see.
// The write is idempotent: with no intervening publication, repeated requests
// return the existing row, so rows grow with the distinct graph states that
// were viewed, not with request count. Nothing deletes manifest rows today.
//
// # Routes
//
//	GET  /healthz                         process liveness
//	GET  /readyz                          database reachable and schema readable; never compiles the graph
//	GET  /api/v1/graph                    current graph view, with ETag
//	GET  /api/v1/manifest                 records (idempotently) and returns the current manifest
//	GET  /api/v1/neighborhood             bounded neighborhood of one resource
//	GET  /api/v1/overview                 counts, manifest (as above), and top active findings
//	GET  /api/v1/resources[/{id}]         paginated, filterable resource catalog
//	GET  /api/v1/relationships[/{id}]     paginated relationship catalog
//	GET  /api/v1/exposures                exposure security semantics
//	GET  /api/v1/events                   server-sent events on graph digest change
//	GET  /api/v1/findings[/{id}]          stored findings, cursor-paginated
//	GET  /api/v1/findings/{id}/remediations/{proposal}/candidates
//	POST /api/v1/findings/{id}/remediations/{proposal}/prepare
//	POST /api/v1/findings/{id}/remediations/{proposal}/approve
//	GET  /api/v1/rules                    active ruleset and loaded workload rules (active or shadow)
//	GET  /api/v1/rule-drafts[/{id}]       Deployment rule drafts; one draft includes its proposal
//	POST /api/v1/rule-drafts/{id}/review  approve or reject a completed draft
//	POST /api/v1/workloads/{id}/rule-drafts  re-author a Deployment's current revision
//	POST /v1/logs                         OTLP logs, when a receiver is configured
//	GET  /, /assets/                      embedded web UI
//	POST /v1/aws/firehose/vpc-flow-logs   AWS VPC flow logs; see below
//
// The command mounts the AWS Firehose route in front of this server's handler
// when --aws-firehose-stream-arn is set; this package does not serve it. It
// authenticates with the Firehose access key and is not subject to the
// loopback Host check.
//
// # Graph events
//
// The events route streams a "graph" event with the graph digest on connect
// and on every change, plus a keepalive comment every 25 seconds. It replaces
// the server's whole-response write timeout with a deadline on each write.
// Each open stream polls [StateStore.GraphRevision] every 500ms and reads the
// shared revision-validated graph only when the revision changes.
//
// # Errors
//
// Errors are JSON objects of the form {"error": "<action>: <reason>"}. A 4xx
// reason describes what is wrong with the request. A 5xx reason is generic,
// apart from a few fixed messages such as "graph is not materialized"; the
// detail is logged on the server.
//
// # Security model
//
// The API is unauthenticated and intended for a loopback listener during
// development. Every response carries a same-origin Content-Security-Policy.
//
// Live remediation is enabled only when the host builds the server with
// [NewServerWithRemediations], which the production command does only for a
// loopback listen address. A finding's remediation is driven entirely by
// server-owned proposals: the browser sends only a provider/source/action
// selection to prepare, and the exact plan ID to approve. Approval resolves
// the plan prepared by this process for the same finding and proposal;
// preparation state is in memory and is lost on restart. A finding that is no
// longer active cannot be remediated.
//
// Mutating requests must have Content-Type application/json. A cross-site
// HTML form or simple fetch cannot send that type without a CORS preflight,
// which this server never approves, so another origin cannot drive approval
// through the user's browser. This is not a full CSRF policy.
//
// DNS rebinding can make a hostile page same-origin with a loopback listener,
// which defeats the content-type defense. [WithLoopbackHostCheck] rejects
// requests whose Host is not localhost or a loopback IP literal; it is on by
// default for servers with live remediation.
//
// Exposing this server beyond loopback requires authenticated infrastructure
// in front of it. See https://agent-shield.dev/docs/operations/security/ and
// https://agent-shield.dev/docs/operations/configuration/.
package api
