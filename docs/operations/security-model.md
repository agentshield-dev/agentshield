# Security model

AgentShield is pre-1.0 and built for evaluation and development. This page states what it protects, what it does not, and how to run it safely.

## The HTTP API has no authentication

Every route served on `--listen` (graph, findings, OTLP receiver, Firehose receiver, UI, and remediation) is unauthenticated and has no authorization. Anyone who can reach the port can:

- read the full graph, including resource names, labels, relationships, and evidence IDs;
- read findings;
- send telemetry that the registered mappers accept;
- if live remediation is enabled, prepare and approve remediations;
- if rule review is enabled, approve or reject Deployment rule drafts and request new ones, which calls the configured model.

Defaults that limit this:

- `--listen` defaults to `127.0.0.1:8088`.
- Live remediation is registered only when discovery is running **and** the listener is a loopback address (`127.0.0.0/8`, `::1`, or `localhost`). On any other address, the remediation endpoints return `503` and the process logs `live remediation API disabled on non-loopback listener`.
- The rule review and regenerate routes act only on a loopback listener, or when `--rule-review-api` is set. On any other address they return `503`.
- The Firehose receiver exists only when `--aws-firehose-stream-arn` is set, and checks the stream ARN, access key, protocol version, and request ID on every request.

If you bind to a non-loopback address, put AgentShield behind infrastructure that authenticates and authorizes every request (for example an authenticating reverse proxy, a service mesh with mTLS and authorization policy, or a private network with strict access control). The UI sends no credentials of its own and expects same-origin requests.

## Browser requests

Two checks stop a website open in your browser from using a loopback AgentShield on your behalf:

- **JSON content type.** Every `POST` route (remediation prepare and approve, rule review and regenerate, the OTLP receiver, and the Firehose receiver) rejects requests that are not `application/json`; OTLP also accepts `application/x-protobuf`. A page on another origin cannot send those types without a CORS preflight, and AgentShield never answers a preflight with permission, so the browser refuses to send the request.
- **Host check.** On a loopback listener the server rejects any request whose `Host` header is not `localhost` or a loopback IP. This blocks DNS rebinding, where a hostile page points its own domain name at `127.0.0.1` to become same-origin and get around the content-type check. The Firehose route is mounted in front of this check; it relies on its access key instead.

These are not authentication and not a complete CSRF policy. They do not stop:

- any process or user on the same machine (or, in a Pod, in the same network namespace) that calls the API directly, for example with `curl`;
- anyone who can reach a non-loopback listener (the Host check is off there, though remediation is disabled);
- a cross-site `GET`. A page can trigger one but cannot read the response. The `GET /api/v1/manifest` and `GET /api/v1/overview` routes record a manifest row as a side effect; repeated requests return the same row.

## Remediation is gated by people, not by policy

- Reasoning, detection, discovery, and graph publication never execute a remediation.
- Execution requires a separate approval request that names a plan prepared in the same process. The browser cannot submit its own proposal or provider payload.
- Prepared actions are in memory. There is no durable approval record and no user identity. Any local process or local user that can open a connection to the loopback listener can prepare and approve an action; see [Browser requests](#browser-requests) for what stops other websites.
- Verification proves that a declared policy exists, not that it is enforced.
- The Kubernetes credentials of the process determine what it can change. Grant read-only RBAC unless you need remediation. Locally, `make run` uses your current kubectl context, so an approved remediation can do anything you can; use a read-only context or `--kubernetes-kubeconfig` if you only want to look.

See [Remediation](../architecture/remediation.md).

## Telemetry and evidence are sensitive

- Telemetry properties, evidence, and raw sink contents can reveal internal topology, request paths, and addresses. Treat the JSONL file and ClickHouse tables as sensitive data.
- Mappers must not put credentials, tokens, authorization headers, request bodies, or principal names into normalized properties. The agentgateway normalizer, for example, records only that a request was authenticated.
- The OTLP receiver never logs record content; rejection responses contain only counts.
- Plugin and source IDs on telemetry come from mapper registration, never from the payload. But anyone who can send records that match a mapper can inject plausible telemetry. Restrict who can write to your collector and to AgentShield.
- Both HTTP receivers acknowledge before the raw sink write. The OTLP receiver returns `200` and the Firehose receiver returns success as soon as the events are in the in-memory queue (up to 100,000 events). Events still queued are lost if the process crashes, or if it is stopped and the 10-second shutdown drain runs out. The sender does not retry them, because it already got a success. See [Telemetry failure behavior](../architecture/telemetry.md#failure-behavior).

## Reasoning MCP server

`agentshield-reasoning-mcp` serves packet-backed graph and telemetry tools over
streamable HTTP at `/mcp`. Its default listener is `127.0.0.1:8090`; the saved
packet and optional telemetry context can contain sensitive graph data. The
server has no authentication or authorization. Keep it on loopback or put it
behind infrastructure that authenticates and authorizes every request before
binding to a non-loopback address.

## Provider data

- Kubernetes Secrets: only metadata and a sorted list of key names are stored. Values, type, and annotations never reach collections, PostgreSQL, or the graph. The informer still reads Secrets into memory, so the service account needs read access to them.
- The AWS plugin uses the default SDK credential chain and never logs credentials.
- Native events in PostgreSQL contain provider object JSON (minus Secret values). That includes ConfigMap `data` and literal Pod `env` values, which are common places for credentials to end up. Protect the database accordingly.

## Model endpoints

AgentShield calls the model endpoint only for the features you enable. With `--agentic-investigation`, it sends graph data: resource IDs, kinds, `network/role`, security semantics, relationships, facets, evidence IDs, and tool results the model requests. With `--deployment-rule-authoring`, it sends, for each Deployment Pod template revision, the Deployment's name, namespace, and service account, plus a summary of its observed outbound requests: destination names and roles, request methods and paths (query strings removed; numeric, UUID, and long hex path segments replaced with `{id}`), outcomes, and counts. Paths can still contain other identifiers, such as names or emails. Setting `--model-endpoint` alone sends nothing. Running detection rules never calls a model. Prompts treat these values as untrusted data. Use a model endpoint approved for this data, keep API keys in environment variables, and note that requests use `store=false` with the Responses API.

## Content Security Policy

The UI and API send `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, plus `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`. UI changes must not add inline scripts or styles, or load assets from other origins.

## Database safety

- Integration tests truncate the database they are given. Never set `AGENTSHIELD_TEST_DATABASE_URL` to a database you want to keep.
- `--database-url` exposes the password in the process list; use `AGENTSHIELD_DATABASE_URL`.

## Out of scope today

Tenant isolation, per-source authorization of telemetry producers, audit logging, rate limiting, and secret-scrubbing of provider payloads beyond Kubernetes Secrets.
