# panopticon-tools: bundled static-analysis tools for grounded code review.
# Build:  docker build -t panopticon-tools .
# Run:    docker run --rm -v "$PWD":/src:ro panopticon-tools <tool> ...
FROM python:3.12-slim

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

RUN useradd -m -u 1000 scanner
USER scanner
WORKDIR /src
ENTRYPOINT []
CMD ["semgrep", "--version"]
