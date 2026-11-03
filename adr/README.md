# Architecture decision records

This directory records decisions that constrain AgentShield's implementation but are not user-facing product documentation. ADRs describe the context, decision, consequences, and evidence available when the decision was made.

An accepted ADR remains in place when implementation changes. A later decision that changes it adds a new ADR and marks the earlier one superseded.

## Decisions

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-snapshot-authority-and-delta-publication.md) | Accepted | Use explicit deltas for ordinary publication and selective complete replacements for authoritative checkpoints and recovery. |
