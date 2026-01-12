SHELL := /bin/sh

BIN := ./bin/dnsgeeo

.PHONY: build test docker-build docker-up docker-down api mcp install-whois

build:
	@go build -o $(BIN) ./cmd/dnsgeeo

test:
	@go test ./...

docker-build:
	@docker build -t dnsgeeo:local .

docker-up:
	@docker compose up --build

docker-down:
	@docker compose down

api:
	@python -m tools.api_server

mcp:
	@python -m tools.mcp_server

install-whois:
	@tools/install_whois_tool.sh
