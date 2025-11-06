.DEFAULT_GOAL := help

ROOT_DIR      := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))


GOLANGCI_LINT_VERSION := v2.4.0
GO_RUN := go run
GOLANGCI_LINT ?= $(GO_RUN) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

default: help

.PHONY: help
help:
	@grep -E '^[a-zA-Z%_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Test
	GO111MODULE=on go test -count=1 -v ./...

.PHONY: fmt
fmt: ## Go format
	go fmt ./...

.PHONY: vet
vet: ## Go vet
	go vet ./...

.PHONY: lint
lint: ## Lint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: ## Lint fix
	$(GOLANGCI_LINT) run --fix

.PHONY: deps
deps: ## Get dependencies
	GO111MODULE=on go get ./...

.PHONY: tidy
tidy: ## Go tidy
	GO111MODULE=on go mod tidy

