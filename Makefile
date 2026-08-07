.PHONY: help build test test-all test-race run vet tidy hooks clean ci ci-full bundle lint eval eval-accept eval-regrade workbench-ci
.DEFAULT_GOAL := help

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*##' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build reckon, reckon-backend, and the bundled adapters to bin/
	@mkdir -p bin
	go build -o bin/reckon ./cmd/reckon
	go build -o bin/reckon-backend ./cmd/reckon-backend
	go build -o bin/reckon-adapter-okta ./cmd/reckon-adapter-okta
	go build -o bin/reckon-adapter-greynoise ./cmd/reckon-adapter-greynoise
	go build -o bin/reckon-adapter-crowdstrike-falcon ./cmd/reckon-adapter-crowdstrike-falcon
	go build -o bin/reckon-adapter-crowdstrike-response ./cmd/reckon-adapter-crowdstrike-response

image: ## Build the engine container image (05 §12.4): supervisor-in-container, runtimes baked, one data volume
	docker build -t reckon:dev .
	@echo ""
	@echo "run it:"
	@echo "  docker run -d --name reckon \\"
	@echo "    -e RECKON_PG_PASSWORD=... -e RECKON_KC_PASSWORD=... \\"
	@echo "    -v reckon-data:/home/reckon/.reckon \\"
	@echo "    -p 127.0.0.1:8080:8080 -p 127.0.0.1:8543:8543 -p 127.0.0.1:9543:9543 \\"
	@echo "    reckon:dev"

test: ## Fast tests: unit + httptest integration. Race detector on. Skips slow embedded-Pg/Temporal/Keycloak lifecycle tests.
	go test -race -short ./...

test-all: ## All tests including slow embedded-deps lifecycle tests. ~60s with binaries cached, several min cold.
	go test -race -count=1 ./...

test-race: test ## Alias for `test` (race detector is always on now)

run: ## Run the backend with the default config
	go run ./cmd/reckon-backend

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint (install: `brew install golangci-lint`)
	@command -v golangci-lint >/dev/null || (echo "golangci-lint not installed; brew install golangci-lint" && exit 1)
	golangci-lint run ./...

tidy: ## Run go mod tidy
	go mod tidy

hooks: ## Install the OSS-leak prevention pre-commit hook
	git config core.hooksPath .githooks/
	@echo "pre-commit hook installed (core.hooksPath = .githooks/)"

clean: ## Remove built binaries
	rm -rf bin/

ci: lint test build ## Pre-commit / PR check: lint + fast tests + build (~10s)

ci-full: lint test-all build ## Pre-release check: lint + full test suite incl. slow lifecycle tests + build

bundle: build ## Build an air-gap-able distribution tarball for the current OS/arch
	@bash scripts/build-bundle.sh

eval: ## Behavioral eval run (design/10): real model + running local stack; costs tokens. Needs ANTHROPIC_API_KEY.
	RECKON_EVAL=1 go test -count=1 -run TestEvalRun -v -timeout 40m ./eval/

eval-accept: ## Accept the latest eval run as the committed per-model baseline (design/10 §4.4). Token-free; refuses a MUST-failing or truncated run (RECKON_EVAL_FORCE=1 to override).
	RECKON_EVAL_ACCEPT=1 go test -count=1 -run '^TestAcceptBaseline$$' -v ./eval/

eval-regrade: ## Re-grade the latest run's committed trials with the current grader catalogue (token-free); rewrites its report.json. Refuses if the driver script changed since the run.
	RECKON_EVAL_REGRADE=1 go test -count=1 -run '^TestRegradeRun$$' -v ./eval/

workbench-ci: ## Install + compile the VS Code extension (workbench/). Requires Node; never part of `ci` — engine work stays Go-only.
	cd workbench && npm ci && npm run compile
