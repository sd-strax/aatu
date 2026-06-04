.PHONY: help build test test-race run vet tidy hooks clean ci
.DEFAULT_GOAL := help

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*##' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build aatu and aatu-backend binaries to bin/
	@mkdir -p bin
	go build -o bin/aatu ./cmd/aatu
	go build -o bin/aatu-backend ./cmd/aatu-backend

test: ## Run all tests
	go test ./...

test-race: ## Run all tests with the race detector
	go test -race -count=1 ./...

run: ## Run the backend with the default config
	go run ./cmd/aatu-backend

vet: ## Run go vet
	go vet ./...

tidy: ## Run go mod tidy
	go mod tidy

hooks: ## Install the OSS-leak prevention pre-commit hook
	git config core.hooksPath .githooks/
	@echo "pre-commit hook installed (core.hooksPath = .githooks/)"

clean: ## Remove built binaries
	rm -rf bin/

ci: vet test build ## What CI runs: vet, test, build
