# BreachPilot disposable sandbox worker image.
#
# Build:  docker build -t breachpilot-sandbox:latest docker/sandbox
#
# SECURITY CONTRACT (see docs/sandbox.md):
# - This image runs ONLY as the BreachPilot sandbox worker (or as the ephemeral
#   NET_ADMIN firewall sidecar sharing the worker's netns). It is never run
#   privileged, never given the Docker socket, and never bound to host paths
#   beyond the validated per-run workspace at /workspace.
# - iptables/ip6tables are included because tools/sandbox/network.py runs the
#   ruleset installer (iptables-restore) from THIS image via --entrypoint in
#   the sidecar. The worker itself runs --cap-drop ALL (NET_RAW at most) and
#   can never invoke them.
# - No secrets, API keys, repo credentials, or user configuration are baked in.

FROM debian:12-slim

ARG DEBIAN_FRONTEND=noninteractive

# Runtime tools the exploit workflow expects inside the worker:
#   python3 + pip        LLM-generated exploit scripts
#   nmap                 port scanning / service detection
#   curl / wget          HTTP probing, PoC fetches (research hosts only)
#   netcat-openbsd       reverse-shell checks, banner grabs
#   git                  PoC repo cloning (pinned research hosts)
#   iproute2             ss/netstat-style inspection inside the sandbox
#   iptables             firewall sidecar (iptables-restore / ip6tables-restore)
#   procps / psmisc      ps, kill, timeout companions (process hygiene)
#   ca-certificates      TLS for git/curl
#   openssh-client       ssh-based lateral movement (authorized targets only)
#   whois / dnsutils     light recon helpers
#   sqlmap, nikto, gobuster, metasploit, hashcat/john, impacket, masscan are
#   deliberately NOT pinned here: they bloat the image and age badly. Install
#   them in a derived image (FROM breachpilot-sandbox:latest) when a mission
#   needs them, or run them via pip inside the workspace. Document any
#   host-only tool in docs/sandbox.md instead of silently falling back.
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
      python3 \
      python3-pip \
      python3-venv \
    ; \
    rm -rf /var/lib/apt/lists/*; \
    # python3 -> python alias for generated scripts that call `python`.
    ln -sf /usr/bin/python3 /usr/local/bin/python

# Non-root worker user. The sandbox runtime (--user sandbox) expects this
# account to exist with a writable HOME; root inside the container is still
# confined by --cap-drop ALL, no-new-privileges, and the netns firewall.
RUN useradd --create-home --shell /bin/bash --uid 1000 sandbox

# Read-only-rootfs mode (default) keeps / writable only via tmpfs + /workspace.
RUN mkdir -p /workspace
WORKDIR /workspace

# No ENTRYPOINT: the manager always passes an explicit argv
# (timeout ... bash -lc <command> / iptables-restore sidecar).
CMD ["/bin/bash"]
