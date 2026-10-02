# AgentShield documentation

## Reading order for newcomers

1. [What AgentShield does](concepts/overview.md): the problem, the pipeline, and the components.
2. [Getting started](getting-started.md): run it locally.
3. [Glossary](concepts/glossary.md): the vocabulary used everywhere else. If you read only one part, read [the five terms you need](concepts/glossary.md#the-five-terms-you-need) at the top.
4. [Data model](concepts/data-model.md): identities, assertions, and contributions.
5. [Architecture overview](architecture/overview.md): what runs where.

Then pick the area you are working on.

## Concepts

- [What AgentShield does](concepts/overview.md)
- [Glossary](concepts/glossary.md)
- [Data model](concepts/data-model.md)
- [Security semantics](concepts/security-semantics.md)

## Architecture

- [Overview](architecture/overview.md): process layout, data flow, HTTP API, known limits
- [Publication and storage](architecture/publication-and-storage.md): contributions, generations, PostgreSQL, change feed, migrations
- [Change feed and reasoning](architecture/change-feed-and-reasoning.md): detectors, model investigation, validation, findings
- [Telemetry](architecture/telemetry.md): ingestion, event schema, rollups, backpressure
- [Detection rules](architecture/detection-rules.md): CEL rules and model-authored Deployment rules
- [Remediation](architecture/remediation.md): suggestions, actions, approval, verification

## Plugins

- [Plugin contract](plugins/README.md)
- [Tutorial: the life of a plugin](plugins/tutorial.md)
- [Style guide](plugins/style-guide.md)
- Providers: [Kubernetes](plugins/kubernetes.md), [Istio](plugins/istio.md), [Cilium](plugins/cilium.md), [agentgateway](plugins/agentgateway.md), [AWS](plugins/aws.md)

## Operations

- [Configuration](operations/configuration.md): every flag and environment variable
- [Helm deployment](../deploy/kubernetes/README.md): installation, PostgreSQL, ClickHouse, and access controls
- [Security model](operations/security-model.md)

## Development

- [Testing](development/testing.md)
- [Evaluation suite](../evals/README.md)
- [Contributing](../CONTRIBUTING.md)
- [Open-source repository migration](development/open-source-migration.md): maintainer publication checklist
