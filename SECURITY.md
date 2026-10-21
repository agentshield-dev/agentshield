# Security policy

AgentShield is pre-1.0 and intended for evaluation and development. Security
fixes are made on `main`; older releases do not have a separate maintenance
or backport commitment.

## Reporting a vulnerability

Do not report vulnerabilities, credentials, or sensitive environment data in
public issues, discussions, or pull requests.

Use [GitHub private vulnerability reporting](https://github.com/agentshield-dev/agentshield/security/advisories/new)
to contact the maintainers privately. If private reporting is unavailable,
open an issue requesting a private reporting channel without including
vulnerability details.

Include the affected version or commit, impact, reproduction steps, and a
minimal example with synthetic data. Remove credentials, kubeconfigs, database
URLs, and real telemetry or provider payloads.

## Running AgentShield safely

The HTTP API and UI have no authentication. Keep the default loopback listener
unless access is protected by authenticated infrastructure. Read the
[security model](https://agent-shield.dev/docs/operations/security/) for trust boundaries,
model endpoint data sharing, and operational limitations.
