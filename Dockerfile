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
RUN gem install --no-document brakeman bundler-audit

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
    '    <PackageReference Include="AdaskoTheBeAsT.SecurityCodeScan.VS2022" Version="5.6.7.200">' \
    '      <PrivateAssets>all</PrivateAssets>' \
    '      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>' \
    '    </PackageReference>' \
    '  </ItemGroup>' \
    '</Project>' > /Directory.Build.props

RUN useradd -m -u 1000 scanner \
    && mkdir -p /home/scanner/.cargo \
    && chown scanner:scanner /home/scanner/.cargo
ENV CARGO_HOME=/home/scanner/.cargo
USER scanner
WORKDIR /src
ENTRYPOINT []
CMD ["semgrep", "--version"]
