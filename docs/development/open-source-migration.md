# Open-source repository migration

The canonical repository is
[`agentshield-dev/agentshield`](https://github.com/agentshield-dev/agentshield).
The Go module and all first-party imports use
`github.com/agentshield-dev/agentshield`. Downstream Go consumers must update
their imports; a GitHub redirect does not change a Go module's declared path.

Go's `internal` packages remain implementation details, and the UI package
remains `private` to prevent accidental npm publication. Neither requires
private repository access.

## Before making the repository public

- Confirm authorization to publish the code, documentation, images, and demo
  video, including third-party redistribution and attribution requirements.
  The Apache 2.0 license and existing copyright attribution remain intact;
  a repository transfer does not transfer copyright.
- Review all history and refs that will be published, including branches,
  tags, Git LFS objects, releases, attachments, and CI artifacts, for secrets,
  customer data, internal endpoints, and material not cleared for release.
  A clean current tree is not evidence that history is safe. Rotate exposed
  credentials before any publication; deleting a file does not revoke them.
- Decide whether to transfer the existing repository or publish a reviewed
  snapshot. Transfer only after the history review; a snapshot must still
  preserve required license and attribution notices.
- Keep runtime data, kubeconfigs, database URLs, model keys, telemetry, and
  evaluation output out of Git and release assets.

## Configure the destination

- Verify that the existing individuals in [CODEOWNERS](../../.github/CODEOWNERS)
  have access to the destination repository; update ownership when a project
  team is established.
- Configure branch protection or rulesets and required checks against the
  workflows in the destination. Confirm that public fork pull requests can
  run CI without organization-only runners, credentials, or dependencies.
- Enable private vulnerability reporting before publication and verify the
  reporting link in [SECURITY.md](../../SECURITY.md).
- Enable available dependency, secret-scanning, and push-protection features.
  Review Actions permissions, environments, secrets, webhooks, installed apps,
  and deployment integrations; do not copy organization credentials blindly.
- Update contributor remotes to the destination. Do not rely on redirects for
  module imports or release-signature verification.

## Validate and release

- Run the checks in [Testing](testing.md), including `make test` and
  `make lint`. Verify the UI and disposable integration suites in CI.
- Verify `make build UI=0 VERSION=migration-check COMMIT=migration-check` and
  `./agentshield --version` report the supplied version and commit. The
  Dockerfile and GoReleaser use the same new module path for linker variables.
- Run a GoReleaser snapshot with the prerequisites described in
  [`.goreleaser.yaml`](../../.goreleaser.yaml) before tagging a release.
  Confirm that archives contain the license, SBOMs, and checksum signatures.
- Verify a destination release's signatures against the destination workflow
  identity. Historical releases retain the identity of the workflow that
  originally signed them; moving the repository does not re-sign artifacts.
- Check clone instructions, issue and security-report links, release downloads,
  and contributor access from an account without source-organization access.

These are publication gates for maintainers, not evidence that the history,
legal review, destination settings, or release checks have already passed.
