PROJECT_NAME={{ cookiecutter.project_name.strip() }}
include .env
current_time = $(shell date --iso-8601=seconds)
git_description = $(shell git describe --always --dirty --tags --long)
linker_flags = '-s -X main.buildTime=${current_time} -X main.version=${git_description}'

.PHONY: help

default: help

.PHONY: confirm
confirm:
	@echo -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]

## help: Print commands help.
.PHONY: help
help : Makefile
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## env: print environment variables (makefile sanity check)
.PHONY: env
env:
	env

## run/{{ cookiecutter.cmd_name.strip() }}: Run the server
.PHONY: run/{{ cookiecutter.cmd_name.strip() }}
run/{{ cookiecutter.cmd_name.strip() }}:
	@go run ./cmd/{{ cookiecutter.cmd_name.strip() }}/main.go

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## run/development: Run the server with hot-reloading (uses `air`)
.PHONY: run/development
run/development:
	@air

# ==================================================================================== #
# BUILD
# ==================================================================================== #

## audit: tidy dependencies and format, vet and test all code
.PHONY: audit
audit:
	@echo "Formatting code..."
	go fmt ./...
	@echo "Vetting code..."
	go vet ./...
	staticcheck ./...
	@echo "Running tests..."
	CGO_ENABLED=1 go test -race -vet=off ./...

## test: run tests with coverage
.PHONY: test
test:
	@echo "Running tests..."
	CGO_ENABLED=1 go test -race -cover -vet=off ./...

## tparse: run tests with coverage using tparse
.PHONY: tparse
tparse:
	@CGO_ENABLED=1 go test -race -cover -vet=off ./... -json | tparse -notests

## vendor: tidy and vendor dependencies
.PHONY: vendor
vendor:
	@echo "Tidying and verifying module dependencies..."
	go mod tidy
	go mod verify
	@echo "Vendoring dependencies..."
	go mod vendor
