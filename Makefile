# Native Go + Rust Makefile for BreachPilot.

GO    ?= go
CARGO ?= cargo
NPM   ?= npm

.PHONY: build install install-dev doctor self-test eval test test-fast test-one run mcp-defensive mcp-exploit mcp-engine codegen clean

build:
	$(GO) build -o bp ./cmd/bp
	$(GO) build -o bp-mcp-defensive ./cmd/bp-mcp-defensive
	$(GO) build -o bp-mcp-assess ./cmd/bp-mcp-assess
	$(GO) build -o bp-mcp-engine ./cmd/bp-mcp-engine
	$(GO) build -o bp-codegen ./cmd/bp-codegen
	$(CARGO) build --manifest-path rust/Cargo.toml --workspace --release

install: build
	cd webui && $(NPM) ci && $(NPM) run build

install-dev: install

doctor:
	$(GO) run ./cmd/bp --doctor

self-test:
	$(GO) run ./cmd/bp --self-test

eval:
	$(GO) run ./cmd/bp --eval

test:
	$(GO) vet ./...
	$(GO) test ./... -count=1
	$(CARGO) test --manifest-path rust/Cargo.toml --workspace

test-fast: test

test-one:
	$(GO) test $(F) -v -count=1

run:
	$(GO) run ./cmd/bp

mcp-defensive:
	$(GO) run ./cmd/bp-mcp-defensive

mcp-exploit:
	$(GO) run ./cmd/bp-mcp-assess

mcp-engine:
	$(GO) run ./cmd/bp-mcp-engine

codegen:
	$(GO) run ./cmd/bp-codegen -mode counts

clean:
	rm -f bp bp-mcp-defensive bp-mcp-assess bp-mcp-engine bp-codegen
	$(CARGO) clean --manifest-path rust/Cargo.toml
