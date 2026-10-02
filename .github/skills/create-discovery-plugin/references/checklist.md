<!-- markdownlint-disable MD013 -->

# Plugin design record

Copy this into the pull request description or an issue for a new plugin, and fill it in before writing code. The rules behind each field are in the [plugin contract](../../../../docs/plugins/README.md).

## Design

- Plugin ID and version:
- Parts (source, semantic, telemetry, remediation):
- Provider authority:
- Source ID:
- Identity scheme and immutable key (new or reused, and why):
- Snapshot API:
- Change API (watch, feed, or polling):
- How deletions are reported:
- Stream cursor, if the provider can resume:
- Collections consumed:
- Collections published:
- Kubernetes resource requirements and capability names, if any:
- Contribution names:
- Resource kinds, predicates, and facets emitted:
- Security semantics emitted (class, domain, carrier):
- Facts kept provider-native, why, and what evidence would change that:
- Who consumes the output:
- Expected inventory size and change rate:
- Required and optional provider APIs:
- Coverage and health states reported:

## Review evidence

Link relevant tests and documentation for the guarantees in the [plugin contract](../../../../docs/plugins/README.md#testing). Note anything that does not apply or could not be tested.
