APP := whatscore
MODULE := github.com/angga0x3/whatscore

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: help build run test test-integration fmt lint vet tidy check docker-up docker-down docker-logs

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the whatscore binary into bin/
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/$(APP)

run: ## Run the server locally (loads .env when present)
	@[ -f .env ] && set -a && . ./.env && set +a ; \
	go run ./cmd/$(APP)

test: ## Run unit tests
	go test -race ./...

test-integration: ## Run integration tests against a throwaway PostgreSQL (Docker required)
	@bash -c 'set -e; \
	docker run -d --rm --name whatscore-test-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine >/dev/null; \
	trap "docker rm -f whatscore-test-pg >/dev/null 2>&1" EXIT; \
	until docker exec whatscore-test-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done; \
	TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" \
	go test -race -tags=integration ./test/integration/...'

fmt: ## Format all Go code
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint (install: https://golangci-lint.run/welcome/install/)
	golangci-lint run

tidy: ## Sync go.mod / go.sum
	go mod tidy

check: fmt vet lint test ## Everything CI runs, locally

docker-up: ## Start the full stack (WhatsCore + PostgreSQL)
	docker compose up -d --build

docker-down: ## Stop the stack and remove containers (keep volumes)
	docker compose down

docker-logs: ## Tail WhatsCore + PostgreSQL logs
	docker compose logs -f --tail=100
