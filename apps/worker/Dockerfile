# Lorikeet Security - Ephemeral Worker Container
# Bundles AST extraction, network tools, and security probing utilities

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    nmap \
    python3 \
    python3-pip \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Install modern nuclei and ffuf
RUN curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d : -f 2,3 \
    | tr -d \" \
    | head -n 1 \
    | xargs -I {} curl -sL {} -o /tmp/nuclei.zip \
    && (cd /tmp && (which unzip >/dev/null || apt-get update && apt-get install -y unzip) && unzip -q nuclei.zip nuclei -d /usr/local/bin/ || true) \
    && rm -rf /tmp/nuclei.zip

WORKDIR /workspace

COPY runner/ /opt/lorikeet/runner/
RUN chmod +x /opt/lorikeet/runner/*.sh

ENTRYPOINT ["/opt/lorikeet/runner/entrypoint.sh"]
CMD ["--help"]
