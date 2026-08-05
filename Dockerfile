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

# Ruby (brakeman + bundler-audit)
RUN gem install --no-document brakeman bundler-audit \
    && bundle-audit update

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
COPY skill/scripts /opt/panopticon/scripts
ENV PYTHONPATH=/opt/panopticon

# OpenJDK (needed by SpotBugs and dependency-check)
RUN apt-get update && apt-get install -y --no-install-recommends default-jdk unzip build-essential \
    && rm -rf /var/lib/apt/lists/*

# SpotBugs + FindSecBugs plugin
ARG SPOTBUGS_VERSION=4.8.6
RUN curl -sfL "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" \
        | tar -xz -C /opt \
    && ln -s "/opt/spotbugs-${SPOTBUGS_VERSION}" /opt/spotbugs \
    && chmod +x /opt/spotbugs/bin/spotbugs
ARG FINDSECBUGS_VERSION=1.13.0
RUN mkdir -p /opt/spotbugs/plugin \
    && curl -sfL "https://search.maven.org/remotecontent?filepath=com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" \
        -o /opt/spotbugs/plugin/findsecbugs-plugin.jar

# OWASP dependency-check
ARG DEPENDENCY_CHECK_VERSION=10.0.3
RUN curl -sfL "https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip" \
        -o /tmp/dc.zip \
    && unzip -q /tmp/dc.zip -d /opt \
    && rm /tmp/dc.zip

# Rust + cargo-audit (system-wide so the scanner user can invoke cargo/rustc)
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
RUN cargo install cargo-audit

# .NET SDK (system-wide so the scanner user can invoke dotnet)
RUN curl -sfL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0 --install-dir /usr/share/dotnet
RUN ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="/usr/share/dotnet:${PATH}"

# SecurityCodeScan Roslyn analyzer - applied to all C# projects built under /src
# via MSBuild's parent-directory Directory.Build.props discovery.
RUN printf '%s\n' \
    '<Project>' \
    '  <ItemGroup>' \
    '    <PackageReference Include="AdaskoTheBeAsT.SecurityCodeScan.VS2022" Version="5.6.7.31">' \
    '      <PrivateAssets>all</PrivateAssets>' \
    '      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>' \
    '    </PackageReference>' \
    '  </ItemGroup>' \
    '</Project>' > /Directory.Build.props

# ---- Offline scan assets (P1: zero scan-time egress; spec 2026-08-04) ----
# Cache boundary: everything ABOVE this ARG stays layer-cached across daily
# builds; every asset fetch BELOW rebuilds when the workflow passes a new
# run date. Each RUN embeds $ASSET_REFRESH so its own layer's cache key
# changes with the date; once one layer misses, every layer after it does
# too (Docker's cache is a chain). Secretless local builds keep the stable
# default (cached, "local").
ARG ASSET_REFRESH=local

# Trivy vulnerability DB
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && mkdir -p /opt/trivy-cache \
    && TRIVY_CACHE_DIR=/opt/trivy-cache trivy --cache-dir /opt/trivy-cache \
       image --download-db-only \
    && chmod -R a+rX /opt/trivy-cache
ENV TRIVY_CACHE_DIR=/opt/trivy-cache

# Semgrep rules: vendor the public semgrep-rules registry source (closest
# offline equivalent of --config auto / p/default — P1 decision: no
# additional packs). The registry's resolved-config cache isn't a flat rule
# tree on disk, so vendor the source repo instead and strip anything that
# isn't a standalone rule config (test fixtures, metadata, project
# dotfiles) — semgrep refuses to load a directory containing an invalid one.
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && git clone --depth 1 https://github.com/semgrep/semgrep-rules /opt/semgrep-rules \
    && rm -rf /opt/semgrep-rules/.git \
    && grep -rLE '^rules:' --include='*.yml' --include='*.yaml' /opt/semgrep-rules \
       | xargs -r rm -f \
    && chmod -R a+rX /opt/semgrep-rules

# RustSec advisory DB for cargo-audit --no-fetch. Path matches the
# CARGO_HOME the scanner user gets below (/home/scanner/.cargo); useradd -m
# tolerates the home directory already existing.
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && git clone --depth 1 https://github.com/rustsec/advisory-db \
       /home/scanner/.cargo/advisory-db \
    && rm -rf /home/scanner/.cargo/advisory-db/.git \
    && chmod -R a+rX /home/scanner/.cargo

# OSV offline databases: npm + PyPI, the ecosystems covered by the fixture
# corpus and the substitute path for the online-only pip-audit/npm-audit
# adapters (see ONLINE_ONLY in tools/__init__.py). Warm with throwaway
# lockfiles so --download-offline-databases has an ecosystem to detect,
# then discard them. This pinned osv-scanner release only recognizes the
# experimental-prefixed flags; the plain spellings are kept as a fallback
# for whenever OSV_SCANNER_VERSION next gets bumped past them.
ENV OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && mkdir -p /opt/osv-db /tmp/osv-warm \
    && printf '%s\n' \
       '{"name":"warm","version":"1.0.0","lockfileVersion":3,"requires":true,' \
       ' "packages":{"":{"name":"warm","version":"1.0.0"},' \
       ' "node_modules/lodash":{"version":"4.17.15"}},' \
       ' "dependencies":{"lodash":{"version":"4.17.15"}}}' \
       > /tmp/osv-warm/package-lock.json \
    && printf 'requests==2.31.0\n' > /tmp/osv-warm/requirements.txt \
    && ( osv-scanner --experimental-offline --experimental-download-offline-databases \
           --format json --recursive /tmp/osv-warm >/dev/null 2>&1 || true ) \
    && if [ ! -s /opt/osv-db/osv-scanner/npm/all.zip ] || [ ! -s /opt/osv-db/osv-scanner/PyPI/all.zip ]; then \
         osv-scanner scan source --offline --download-offline-databases \
           --format json --recursive /tmp/osv-warm >/dev/null 2>&1 || true; \
       fi \
    && rm -rf /tmp/osv-warm \
    && chmod -R a+rX /opt/osv-db

# dependency-check NVD data (BuildKit secret; build works without it, just
# slower — the NVD API rate-limits unauthenticated callers hard enough that
# a full sync can take the better part of an hour, so the update is bounded
# and allowed to fail or partial-fill rather than hang a scheduled build).
RUN --mount=type=secret,id=nvd_api_key \
    : "asset-refresh ${ASSET_REFRESH}" \
    && mkdir -p /opt/odc-data \
    && KEY="$(cat /run/secrets/nvd_api_key 2>/dev/null || true)" \
    && ( timeout 600 /opt/dependency-check/bin/dependency-check.sh --updateonly \
           --data /opt/odc-data ${KEY:+--nvdApiKey "$KEY"} || true ) \
    && chmod -R a+rX /opt/odc-data

# SecurityCodeScan offline NuGet feed: warm a package folder via a throwaway
# project (the root /Directory.Build.props injects the analyzer reference),
# then pin restore to it via fallbackPackageFolders.
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && mkdir -p /tmp/warm && cd /tmp/warm \
    && dotnet new classlib -o warmproj --no-restore \
    && dotnet restore warmproj --packages /opt/nuget-packages \
    && cd / && rm -rf /tmp/warm \
    && chmod -R a+rX /opt/nuget-packages
RUN printf '%s\n' \
    '<?xml version="1.0" encoding="utf-8"?>' \
    '<configuration>' \
    '  <packageSources><clear /></packageSources>' \
    '  <fallbackPackageFolders>' \
    '    <add key="baked" value="/opt/nuget-packages" />' \
    '  </fallbackPackageFolders>' \
    '</configuration>' > /nuget.config \
    && chmod a+r /nuget.config

RUN useradd -m -u 1000 scanner \
    && mkdir -p /home/scanner/.cargo \
    && chown scanner:scanner /home/scanner/.cargo \
    && mkdir -p /home/scanner/.local/share \
    && cp -r /root/.local/share/ruby-advisory-db /home/scanner/.local/share/ \
    && chown -R scanner:scanner /home/scanner/.local/share/ruby-advisory-db
ENV CARGO_HOME=/home/scanner/.cargo
USER scanner
WORKDIR /src
ENTRYPOINT []
CMD ["semgrep", "--version"]
