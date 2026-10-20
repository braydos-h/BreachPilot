# BreachPilot production multi-stage build: Go control plane + Rust execution sidecar + WebUI.
FROM rust:1.89-slim-bookworm AS rust-builder
WORKDIR /src/rust
COPY rust/ ./
RUN cargo build --release --bin bp-sidecar

FROM golang:1.24-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY proto/ proto/
RUN CGO_ENABLED=0 go build -trimpath -o /out/bp ./cmd/bp && \
    CGO_ENABLED=0 go build -trimpath -o /out/bp-mcp-defensive ./cmd/bp-mcp-defensive && \
    CGO_ENABLED=0 go build -trimpath -o /out/bp-mcp-assess ./cmd/bp-mcp-assess && \
    CGO_ENABLED=0 go build -trimpath -o /out/bp-mcp-engine ./cmd/bp-mcp-engine && \
    CGO_ENABLED=0 go build -trimpath -o /out/bp-codegen ./cmd/bp-codegen

FROM node:22-bookworm-slim AS webui-builder
WORKDIR /src/webui
COPY webui/package.json webui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY webui/ ./
RUN npm run build

FROM debian:12-slim
RUN useradd -m -u 1000 breachpilot && apt-get update && apt-get install -y --no-install-recommends ca-certificates nmap iproute2 iptables curl git tmux && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /out/bp /usr/local/bin/bp
COPY --from=go-builder /out/bp-mcp-defensive /usr/local/bin/bp-mcp-defensive
COPY --from=go-builder /out/bp-mcp-assess /usr/local/bin/bp-mcp-assess
COPY --from=go-builder /out/bp-mcp-engine /usr/local/bin/bp-mcp-engine
COPY --from=go-builder /out/bp-codegen /usr/local/bin/bp-codegen
COPY --from=rust-builder /src/rust/target/release/bp-sidecar /usr/local/bin/bp-sidecar
COPY --from=webui-builder /src/webui/dist /opt/breachpilot/webui/dist
COPY config.yaml /etc/breachpilot/config.yaml
USER breachpilot
EXPOSE 8765
CMD ["bp", "--config", "/etc/breachpilot/config.yaml"]
