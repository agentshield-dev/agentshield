# syntax=docker/dockerfile:1

# Production image for AgentShield. The agentshield binary embeds the web UI from ui/dist, so the
# UI is built first and copied in before the Go build. Build stages run on the build host's
# platform and cross-compile, so `docker buildx build --platform linux/amd64,linux/arm64` works
# without emulation.

FROM --platform=$BUILDPLATFORM node:24.22.1-trixie-slim AS ui
WORKDIR /src/ui
# corepack provides the pnpm version pinned by packageManager in ui/package.json.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY ui/package.json ui/pnpm-lock.yaml ui/pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY ui/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie AS build
ARG TARGETOS
ARG TARGETARCH
# .git is excluded from the build context, so the version and commit come from build arguments.
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
COPY --from=ui /src/ui/dist/ ./ui/dist/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -f ui/dist/index.html && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -o /out/ \
    -ldflags="-s -w -X github.com/agentshield-dev/agentshield/internal/version.Version=${VERSION} -X github.com/agentshield-dev/agentshield/internal/version.Commit=${COMMIT}" \
    ./cmd/agentshield \
    ./cmd/agentshield-reasoning-mcp \
    ./cmd/agentshield-detector-rules \
    ./cmd/agentshield-deployment-author

# distroless/static supplies CA certificates and a nonroot user (65532, the same UID the evals
# image uses) and nothing else. The digest pins ca-certificates 20250419+deb13u1 or later, which
# distrusts the compromised eMudhra intermediates.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/ /usr/local/bin/
# The default --telemetry-jsonl path is relative (.agentshield/), so start in a writable directory.
WORKDIR /home/nonroot
USER 65532:65532
# agentshield listens on 127.0.0.1:8088 by default, which is unreachable from outside the
# container. The HTTP API is unauthenticated: pass --listen 0.0.0.0:8088 only behind authenticated
# infrastructure (see https://agent-shield.dev/docs/operations/security/). Live remediation is disabled on a
# non-loopback listen address.
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/agentshield"]
