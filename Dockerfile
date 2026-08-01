# panopticon-tools: bundled static-analysis tools for grounded code review.
# Build:  docker build -t panopticon-tools .
# Run:    docker run --rm -v "$PWD":/src:ro panopticon-tools <tool> ...
FROM python:3.14-slim

ARG GITLEAKS_VERSION=8.18.4
ARG GOSEC_VERSION=2.20.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git gnupg ruby nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Python tools
RUN pip install --no-cache-dir semgrep bandit bandit-sarif-formatter

# Ruby (brakeman)
RUN gem install --no-document brakeman

# Node (eslint + security plugin)
RUN npm install -g eslint eslint-plugin-security @microsoft/eslint-formatter-sarif

# Python dependency audit
RUN pip install --no-cache-dir pip-audit

# OSV scanner (static Go binary)
ARG OSV_SCANNER_VERSION=1.8.2
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) osv="amd64" ;; arm64) osv="arm64" ;; *) osv="${arch}" ;; esac \
    && curl -sfL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv}" \
        -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# gitleaks (architecture-aware: amd64->x64, arm64->arm64)
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) gl="x64" ;; arm64) gl="arm64" ;; *) gl="$arch" ;; esac \
    && curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl}.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks

# trivy (official apt repo — robust, arch-aware)
RUN curl -sfL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

# gosec (architecture-aware)
RUN arch="$(dpkg --print-architecture)" \
    && curl -sfL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${arch}.tar.gz" \
        | tar -xz -C /usr/local/bin gosec

# Copy panopticon adapter dispatcher into the image so Docker-based runs can
# invoke Phase 1 adapters without relying on the target repo providing it.
COPY scripts /opt/panopticon/scripts
ENV PYTHONPATH=/opt/panopticon

RUN useradd -m -u 1000 scanner
USER scanner
WORKDIR /src
ENTRYPOINT []
CMD ["semgrep", "--version"]
