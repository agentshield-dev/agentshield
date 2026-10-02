GO ?= go
PNPM ?= pnpm
LISTEN ?= 127.0.0.1:8088
DEMO_PORT ?= 5173
DATABASE_URL ?= $(AGENTSHIELD_DATABASE_URL)

# The web UI in ui/ is embedded from ui/dist. UI=0 skips the Node build and embeds whatever
# ui/dist already holds; without a build the binary serves a "UI is not built" notice.
UI ?= 1
ifeq ($(UI),0)
UI_PREREQ :=
else
UI_PREREQ := ui
endif
# Stamped into binaries by `make build`; release builds set the same variables in .goreleaser.yaml.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
VERSION_PKG := github.com/agentshield-dev/agentshield/internal/version
LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT)

UI_INDEX := ui/dist/index.html
UI_SOURCES := $(shell find ui/src ui/mocks ui/public -type f 2>/dev/null) ui/index.html ui/package.json ui/pnpm-lock.yaml ui/vite.config.ts $(wildcard ui/tsconfig*.json)

.PHONY: build test lint lint-fix test-postgres benchmark-postgres test-aws-e2e run postgres-up postgres-down eval-up eval-check eval-run eval-rules eval-matrix eval-down graph-ui ui ui-dev ui-lint ui-storybook ui-test demo clean

build: $(UI_PREREQ)
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/agentshield

ui: $(UI_INDEX)

$(UI_INDEX): $(UI_SOURCES)
	cd ui && $(PNPM) install --frozen-lockfile && $(PNPM) build

ui-dev:
	cd ui && $(PNPM) install --frozen-lockfile && AGENTSHIELD_API="http://$(LISTEN)" $(PNPM) dev

ui-lint:
	cd ui && $(PNPM) install --frozen-lockfile && $(PNPM) lint

ui-storybook:
	cd ui && $(PNPM) install --frozen-lockfile && $(PNPM) storybook

demo:
	cd ui && $(PNPM) install --frozen-lockfile && VITE_AGENTSHIELD_DEMO=1 $(PNPM) dev --host 127.0.0.1 --port $(DEMO_PORT) --strictPort

ui-test:
	cd ui && $(PNPM) install --frozen-lockfile && $(PNPM) exec playwright install chromium && $(PNPM) test

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...

test-postgres:
	bash ./scripts/test-postgres.sh

benchmark-postgres:
	bash ./scripts/benchmark-postgres.sh

test-aws-e2e:
	bash ./scripts/test-aws-e2e.sh

run: $(UI_PREREQ)
	@test -n "$(DATABASE_URL)" || (echo "set DATABASE_URL or AGENTSHIELD_DATABASE_URL" >&2; exit 1)
	AGENTSHIELD_DATABASE_URL="$(DATABASE_URL)" $(GO) run ./cmd/agentshield --listen $(LISTEN)

postgres-up:
	docker compose -f deploy/postgres/compose.yaml up -d --wait

postgres-down:
	docker compose -f deploy/postgres/compose.yaml down

eval-up:
	./evals/scripts/run.sh

eval-check:
	./evals/scripts/eval-run.sh --validate-only

eval-run:
	./evals/scripts/eval-run.sh

eval-rules:
	./evals/scripts/eval-run.sh --suite rules

eval-matrix:
	./evals/scripts/eval-matrix.sh

eval-down:
	./evals/scripts/down.sh

graph-ui: $(UI_PREREQ)
	@test -n "$(DATABASE_URL)" || (echo "set DATABASE_URL or AGENTSHIELD_DATABASE_URL" >&2; exit 1)
	AGENTSHIELD_DATABASE_URL="$(DATABASE_URL)" $(GO) run ./cmd/agentshield --disable-discovery --listen $(LISTEN)

clean:
	rm -rf .agentshield
