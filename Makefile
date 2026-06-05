.PHONY: help build test test-all test-race run vet tidy hooks clean ci ci-full bundle lint
.DEFAULT_GOAL := help

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*##' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build reckon and reckon-backend binaries to bin/
	@mkdir -p bin
	go build -o bin/reckon ./cmd/reckon
	go build -o bin/reckon-backend ./cmd/reckon-backend

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
