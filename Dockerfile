FROM debian:trixie-slim

# Project-specific packages come from sandbox.toml [worker] packages
ARG PACKAGES=""
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git ripgrep less procps python3 python3-pip nodejs npm $PACKAGES \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code && npm cache clean --force
# Ghidra MCP bridge dependencies
RUN pip install --break-system-packages --no-cache-dir mcp requests

# uid 2000: distinct from the VM's decomp user (1000), so workers can't write the mirror or shared files
RUN useradd -u 2000 -m -d /home/agent -s /bin/bash agent
COPY worker_entry.py /usr/local/bin/worker-entry
USER agent
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/worker-entry"]
