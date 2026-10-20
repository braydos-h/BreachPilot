# BreachPilot disposable sandbox worker image.
#
# Build:  docker build -t breachpilot-sandbox:latest docker/sandbox
#
# SECURITY CONTRACT (see docs/sandbox.md):
# - This image runs ONLY as the BreachPilot sandbox worker (or as the ephemeral
#   NET_ADMIN firewall sidecar sharing the worker's netns). It is never run
#   privileged, never given the Docker socket, and never bound to host paths
#   beyond the validated per-run workspace at /workspace.
# - iptables/ip6tables are included because bp-exec runs the ruleset installer
#   (iptables-restore) from THIS image via --entrypoint in the sidecar.
#   The worker itself runs --cap-drop ALL (NET_RAW at most) and can never invoke them.
# - No secrets, API keys, repo credentials, or user configuration are baked in.

FROM debian:12-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      bash \
      coreutils \
      util-linux \
      ca-certificates \
      curl \
      wget \
      git \
      nmap \
      netcat-openbsd \
      iproute2 \
      iptables \
      procps \
      psmisc \
      openssh-client \
      whois \
      dnsutils \
    ; \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash --uid 1000 sandbox
RUN mkdir -p /workspace
WORKDIR /workspace

CMD ["sleep", "infinity"]
