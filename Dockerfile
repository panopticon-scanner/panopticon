# panopticon-tools: bundled static-analysis tools for grounded code review.
# Build:  docker build -t panopticon-tools .
# Run:    docker run --rm -v "$PWD":/src:ro panopticon-tools <tool> ...
# NVD database comes from the cron-published, version-keyed cache image (the
# "Refresh NVD data cache" workflow) — so no build hits the NVD API or needs a
# secret. docker-publish resolves the digest of the current dc-* tag and passes
# it as a build-arg, so each publish is content-pinned. The default below is the
# current digest for dc-10.0.3; it keeps PR gates and local builds reproducible
# without needing a registry lookup. Bump it when DEPENDENCY_CHECK_VERSION or
# the cache image changes.
ARG NVD_DATA_REF=ghcr.io/panopticon-scanner/panopticon-tools-nvd@sha256:5dae9831d546241017f80ab86553826c8ead7e38ae61e9feb94880274c78fec0
# DL3006: the version tag lives inside NVD_DATA_REF (docker-publish pins a @sha256
# digest), so hadolint cannot see it statically.
# hadolint ignore=DL3006
FROM ${NVD_DATA_REF} AS nvd-data

FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG GITLEAKS_VERSION=8.18.4
ARG GOSEC_VERSION=2.20.0
ARG SEMGREP_VERSION=1.173.0
ARG BANDIT_VERSION=1.9.4
ARG BANDIT_SARIF_FORMATTER_VERSION=1.1.1
ARG BRAKEMAN_VERSION=8.0.6
ARG BUNDLER_AUDIT_VERSION=0.9.3
ARG ESLINT_VERSION=10.9.0
ARG ESLINT_PLUGIN_SECURITY_VERSION=4.0.1
ARG ESLINT_FORMATTER_SARIF_VERSION=3.1.0
ARG PIP_AUDIT_VERSION=2.10.1
ARG CARGO_AUDIT_VERSION=0.22.2

# Distro apt packages are intentionally unpinned: they carry security updates, and
# pinning exact versions breaks the build when the mirror rotates them off. The
# security TOOL binaries are pinned by checksum instead (see the ARG pins above).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git gnupg ruby nodejs npm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Python tools. semgrep pinned (#outage 2026-08-18): the rules-corpus pin
# below is a commit SHA on a live branch, but that pin is only meaningful
# paired with a known-compatible semgrep build -- an unpinned `pip install`
# would keep re-validating tomorrow's semgrep release against today's rules.
RUN pip install --timeout=300 --no-cache-dir "semgrep==${SEMGREP_VERSION}" "bandit==${BANDIT_VERSION}" "bandit-sarif-formatter==${BANDIT_SARIF_FORMATTER_VERSION}"

# Ruby (brakeman + bundler-audit)
RUN timeout 300 gem install --no-document "brakeman:${BRAKEMAN_VERSION}" "bundler-audit:${BUNDLER_AUDIT_VERSION}" \
    && timeout 120 bundle-audit update

# Node (eslint + security plugin) + Python dependency audit
RUN npm install --fetch-timeout=600000 -g "eslint@${ESLINT_VERSION}" "eslint-plugin-security@${ESLINT_PLUGIN_SECURITY_VERSION}" "@microsoft/eslint-formatter-sarif@${ESLINT_FORMATTER_SARIF_VERSION}" \
    && pip install --timeout=300 --no-cache-dir "pip-audit==${PIP_AUDIT_VERSION}"

# OSV scanner (static Go binary)
ARG OSV_SCANNER_VERSION=1.8.2
ARG OSV_SCANNER_SHA256_AMD64=558dbed2194d05ce00d8f8c27dcb49d763eb9db3bc7e30a1bf9b6b86062ccede
ARG OSV_SCANNER_SHA256_ARM64=9e72c15c7239d7810f556a97d5a37d4fc9de440404c05393d4ee994e2ccc51f2
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) osv="amd64"; sha256="${OSV_SCANNER_SHA256_AMD64}" ;; arm64) osv="arm64"; sha256="${OSV_SCANNER_SHA256_ARM64}" ;; *) echo "unsupported arch: $arch" >&2; exit 1 ;; esac \
    && curl -sfL --connect-timeout 5 --max-time 60 "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv}" \
        -o /tmp/osv-scanner \
    && echo "${sha256}  /tmp/osv-scanner" | sha256sum -c - \
    && mv /tmp/osv-scanner /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# gitleaks (architecture-aware: amd64->x64, arm64->arm64)
ARG GITLEAKS_SHA256_X64=ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d
ARG GITLEAKS_SHA256_ARM64=bf5f7f466ebfade1296c8bd32cf7d3f592c2aa78836aa9980ffbe2cadca7a861
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) gl="x64"; sha256="${GITLEAKS_SHA256_X64}" ;; arm64) gl="arm64"; sha256="${GITLEAKS_SHA256_ARM64}" ;; *) echo "unsupported arch: $arch" >&2; exit 1 ;; esac \
    && curl -sfL --connect-timeout 5 --max-time 60 "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl}.tar.gz" \
        -o /tmp/gitleaks.tar.gz \
    && echo "${sha256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz

# trivy (official apt repo — robust, arch-aware); apt package unpinned, see the base apt note above.
# hadolint ignore=DL3008
RUN curl -sfL --connect-timeout 5 --max-time 60 https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# gosec (architecture-aware)
ARG GOSEC_SHA256_AMD64=2d056644cf265f194efaf98b80d459004c03db7b367fbc3fe7fb345773df684e
ARG GOSEC_SHA256_ARM64=a0c554e23ad088b544d40ca63039362ed2687fb576a33c1019951dbd3edcd716
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) sha256="${GOSEC_SHA256_AMD64}" ;; arm64) sha256="${GOSEC_SHA256_ARM64}" ;; *) echo "unsupported arch: $arch" >&2; exit 1 ;; esac \
    && curl -sfL --connect-timeout 5 --max-time 60 "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${arch}.tar.gz" \
        -o /tmp/gosec.tar.gz \
    && echo "${sha256}  /tmp/gosec.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec \
    && rm /tmp/gosec.tar.gz

# Copy panopticon adapter dispatcher into the image so Docker-based runs can
# invoke Phase 1 adapters without relying on the target repo providing it.
COPY skill/scripts /opt/panopticon/scripts
ENV PYTHONPATH=/opt/panopticon

# OpenJDK (needed by SpotBugs and dependency-check); apt packages unpinned, see the base apt note above.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends default-jdk unzip build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# SpotBugs + FindSecBugs plugin
ARG SPOTBUGS_VERSION=4.8.6
# Pinned SHA-256 of spotbugs-${SPOTBUGS_VERSION}.tgz. The tarball is extracted as
# an unsandboxed Java analyzer in the image, so a substituted archive would run
# attacker-controlled code in downstream scans.
ARG SPOTBUGS_SHA256=b9d4d25e53cd4202b2dc19c549c0ff54f8a72fc76a71a8c40dee94422c67ebea
RUN curl -sfL --connect-timeout 5 --max-time 60 "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" \
        -o /tmp/spotbugs.tgz \
    && echo "${SPOTBUGS_SHA256}  /tmp/spotbugs.tgz" | sha256sum -c - \
    && tar -xzf /tmp/spotbugs.tgz -C /opt \
    && ln -s "/opt/spotbugs-${SPOTBUGS_VERSION}" /opt/spotbugs \
    && chmod +x /opt/spotbugs/bin/spotbugs \
    && rm /tmp/spotbugs.tgz
ARG FINDSECBUGS_VERSION=1.13.0
# Pinned SHA-256 of findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar. This jar is
# loaded as an unsandboxed SpotBugs analyzer plugin (arbitrary bytecode in the
# scan JVM), and the image is published publicly and rebuilt daily, so an
# unverified fetch would propagate a substituted jar to every downstream Java
# scan (#539). Fetched from the canonical Maven2 GAV path and verified with
# sha256sum -c; the build FAILS on mismatch. To bump the version, update both
# ARGs (the new digest is the jar's .sha256, or `sha256sum` of the artifact).
ARG FINDSECBUGS_SHA256=c239763a8c327b5fb653a34dece6398578bf435b9a32c212bb8e1abe701368a5
RUN mkdir -p /opt/spotbugs/plugin \
    && curl -sfL --connect-timeout 5 --max-time 60 "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" \
        -o /opt/spotbugs/plugin/findsecbugs-plugin.jar \
    && echo "${FINDSECBUGS_SHA256}  /opt/spotbugs/plugin/findsecbugs-plugin.jar" | sha256sum -c -

# OWASP dependency-check
ARG DEPENDENCY_CHECK_VERSION=10.0.3
ARG DEPENDENCY_CHECK_SHA256=5263fbafb15010823364274b83e9a2219b654d00a557d92941c37736d4076ba4
RUN curl -sfL --connect-timeout 5 --max-time 120 "https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip" \
        -o /tmp/dc.zip \
    && echo "${DEPENDENCY_CHECK_SHA256}  /tmp/dc.zip" | sha256sum -c - \
    && unzip -q /tmp/dc.zip -d /opt \
    && rm /tmp/dc.zip

# Rust + cargo-audit (system-wide so the scanner user can invoke cargo/rustc)
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}"
# FIXME (#run7 review): these SHAs pin the binary but are fetched from the
# MOVING `rustup/dist/<triple>/rustup-init` URL, which always serves the LATEST
# rustup. When rust-lang next ships a rustup release the served binary changes
# and `sha256sum -c` fails, hard-breaking the next from-scratch Docker build on
# an unrelated checksum mismatch. Pin like the dotnet installer below (an
# immutable versioned URL): add `ARG RUSTUP_VERSION=<x.y.z>`, fetch from
# `rustup/archive/${RUSTUP_VERSION}/<triple>/rustup-init`, and set the SHAs for
# THAT version (requires looking them up from rust-lang -- do not guess).
ARG RUSTUP_INIT_SHA256_AMD64=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUSTUP_INIT_SHA256_ARM64=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) ru="x86_64-unknown-linux-gnu"; sha256="${RUSTUP_INIT_SHA256_AMD64}" ;; arm64) ru="aarch64-unknown-linux-gnu"; sha256="${RUSTUP_INIT_SHA256_ARM64}" ;; *) echo "unsupported arch: $arch" >&2; exit 1 ;; esac \
    && curl -sfL --connect-timeout 5 --max-time 60 "https://static.rust-lang.org/rustup/dist/${ru}/rustup-init" \
        -o /tmp/rustup-init \
    && echo "${sha256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --default-toolchain stable \
    && rm /tmp/rustup-init
RUN timeout 600 cargo install cargo-audit --version ${CARGO_AUDIT_VERSION}

# .NET SDK (system-wide so the scanner user can invoke dotnet)
ARG DOTNET_INSTALL_SHA256=082f7685e156738a1b2e2ed8381a621870d4ce8e8c59278034556f05c186eb2e
RUN curl -sfL --connect-timeout 5 --max-time 60 "https://raw.githubusercontent.com/dotnet/install-scripts/47940ac9fc30a2f2dd19167165d0bb0774625f67/src/dotnet-install.sh" \
        -o /tmp/dotnet-install.sh \
    && echo "${DOTNET_INSTALL_SHA256}  /tmp/dotnet-install.sh" | sha256sum -c - \
    && chmod +x /tmp/dotnet-install.sh \
    && timeout 600 /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh
RUN ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="/usr/share/dotnet:${PATH}"

# DotnetariumSCS standalone C# security scanner. Replaces the SecurityCodeScan
# NuGet analyzer, which no longer emits findings on .NET 8 (the build was
# failing the smoke test with "no SCS findings in SARIF"). DotnetariumSCS is a
# SecurityCodeScan-compatible fork that works on .NET 8 and emits the same
# SCS* rule IDs in SARIF 2.1 format, so the adapter parse logic is unchanged.
ARG DOTNETARIUM_SCS_VERSION=1.1.0
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
RUN timeout 300 dotnet tool install --tool-path /usr/local/bin dotnetarium-scs --version ${DOTNETARIUM_SCS_VERSION}

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
#
# Pinned to a COMMIT, not a branch name (outage 2026-08-18/19): the repo's
# actual active branch is `develop` (its GitHub default_branch); `master`
# and `main` are both long-abandoned (frozen since 2020-05-19 and
# 2022-05-11). A prior fix pinned `--branch master`, believing it named a
# stable default — instead it silently swapped a live, semgrep-compatible
# ruleset for a six-year-old snapshot, which broke every build once its
# rule shapes finally diverged from the semgrep pip package's current
# schema (exit 7: invalid rule in config). A branch name floats and can
# rot the same way again, so pin the SHA and bump it by hand when
# refreshing — see https://github.com/semgrep/semgrep-rules/commits/develop
# DO NOT replace this with a placeholder SHA: #1272 did exactly that
# (1234567890abcdef…), which does not exist and fails the checkout.
ARG SEMGREP_RULES_REF=40b8c63f75dc7c22c8a77482d73bfb864b146f7e
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && git init -q /opt/semgrep-rules \
    && git -C /opt/semgrep-rules remote add origin https://github.com/semgrep/semgrep-rules \
    && timeout 120 git -C /opt/semgrep-rules -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=30 fetch --depth 1 origin "${SEMGREP_RULES_REF}" \
    && git -C /opt/semgrep-rules checkout -q FETCH_HEAD \
    && rm -rf /opt/semgrep-rules/.git \
    && grep -rLE '^rules:' --include='*.yml' --include='*.yaml' /opt/semgrep-rules \
       | xargs -r rm -f \
    && chmod -R a+rX /opt/semgrep-rules

# RustSec advisory DB for cargo-audit --no-fetch. Path matches the
# CARGO_HOME the scanner user gets below (/home/scanner/.cargo); useradd -m
# tolerates the home directory already existing.
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && timeout 60 git clone --depth 1 https://github.com/rustsec/advisory-db \
       /home/scanner/.cargo/advisory-db \
    && rm -rf /home/scanner/.cargo/advisory-db/.git \
    && chmod -R a+rX /home/scanner/.cargo

# Ruby advisory DB for bundler-audit --no-update. The initial `gem install
# ... && bundle-audit update` (toolchain region, above the cache boundary)
# only ever runs once and then stays frozen by layer caching, so re-run the
# update here so ruby-advisory-db tracks $ASSET_REFRESH like every other
# baked asset. Must land before the useradd block below copies it to
# /home/scanner, so the scanner user gets the refreshed DB, not the stale
# toolchain-layer snapshot.
RUN : "asset-refresh ${ASSET_REFRESH}" \
    && timeout 120 bundle-audit update \
    && chmod -R a+rX /root/.local/share/ruby-advisory-db

# OSV offline databases. The container has no egress, so osv-scanner runs
# --experimental-offline and can only report on ecosystems whose database is
# baked in here. Warm with throwaway manifests so
# --download-offline-databases has an ecosystem to detect, then discard them.
#
# #calibration-1 (fzf): this warmed npm + PyPI ONLY -- "the ecosystems covered
# by the fixture corpus". Every fixture is npm/PyPI, so it always passed
# in-house, and the gap only appeared on a real target: scanning fzf (Go +
# RubyGems) produced "could not load db for RubyGems ecosystem: no offline
# version of the OSV database is available" for every package, exit 127, no
# output file -- so osv-scanner landed in tool_manifest.missing and SANK
# CERTIFICATION. It would have done so on every Go/Ruby/Rust/Java/Maven target
# in the calibration pool. Warm every ecosystem the OsvScannerAdapter declares
# itself applicable to (see tools/osv_scanner.py is_applicable).
#
# This pinned osv-scanner release only recognizes the experimental-prefixed
# flags. #run7 review: the plain-flag fallback invocation was removed in favor
# of a hard fail -- if a future OSV_SCANNER_VERSION bump renames/drops these
# flags, the warm below produces no databases and the ::error:: check fails the
# build (rather than silently shipping an empty DB). Update the flag spellings
# here when bumping the version.
ENV OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db
RUN set -euo pipefail \
    && : "asset-refresh ${ASSET_REFRESH}" \
    && mkdir -p /opt/osv-db /tmp/osv-warm \
    && printf '%s\n' \
       '{"name":"warm","version":"1.0.0","lockfileVersion":3,"requires":true,' \
       ' "packages":{"":{"name":"warm","version":"1.0.0"},' \
       ' "node_modules/lodash":{"version":"4.17.15"}},' \
       ' "dependencies":{"lodash":{"version":"4.17.15"}}}' \
       > /tmp/osv-warm/package-lock.json \
    && printf 'requests==2.31.0\n' > /tmp/osv-warm/requirements.txt \
    && printf 'module warm\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.7\n' \
       > /tmp/osv-warm/go.mod \
    && printf 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n' \
       > /tmp/osv-warm/Gemfile.lock \
    && printf '# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = "warm"\nversion = "0.1.0"\n\n[[package]]\nname = "time"\nversion = "0.1.44"\n' \
       > /tmp/osv-warm/Cargo.lock \
    && printf '<project><modelVersion>4.0.0</modelVersion><groupId>warm</groupId><artifactId>warm</artifactId><version>1.0</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>\n' \
       > /tmp/osv-warm/pom.xml \
    # --no-ignore avoids a git-root resolution error for the throwaway /tmp/osv-warm
    # directory. The scanner exits 1 when it finds vulnerabilities, but we only care
    # that every declared ecosystem database was actually downloaded into /opt/osv-db.
    && (timeout 300 osv-scanner --experimental-offline --experimental-download-offline-databases \
           --no-ignore --format json --recursive /tmp/osv-warm >/tmp/osv-warm.log 2>&1 || true) \
    && for eco in npm PyPI Go RubyGems crates.io Maven; do \
         if [ ! -s "/opt/osv-db/osv-scanner/$eco/all.zip" ]; then \
           echo "::error::OSV offline DB warm did not produce the $eco database" >&2; \
           cat /tmp/osv-warm.log >&2; \
           exit 1; \
         fi; \
       done \
    && rm -rf /tmp/osv-warm /tmp/osv-warm.log \
    && chmod -R a+rX /opt/osv-db

# dependency-check NVD database: copied from the pinned cache stage (NVD_DATA_REF,
# top of file) — no NVD API call, no secret, no per-build sync. The later
# `chown -R scanner:scanner /opt/odc-data` gives dependency-check the read-write
# access it needs on odc.mv.db.
COPY --from=nvd-data /opt/odc-data /opt/odc-data

RUN useradd -m -u 1000 scanner \
    && chown scanner:scanner /home/scanner \
    && mkdir -p /home/scanner/.cargo \
    && chown scanner:scanner /home/scanner/.cargo \
    && mkdir -p /home/scanner/.local/share \
    && cp -r /root/.local/share/ruby-advisory-db /home/scanner/.local/share/ \
    && chown -R scanner:scanner /home/scanner/.local/share/ruby-advisory-db \
    && chown -R scanner:scanner /opt/odc-data
# /opt/odc-data is chowned, not just a+rX: dependency-check opens its H2
# database (odc.mv.db) read-write even under --noupdate, and when the lock
# cannot be taken H2 BLOCKS rather than failing, so the adapter burns its full
# 900s timeout and returns nothing. Chowning here rather than in the NVD layer
# keeps that expensive download cached.
# /home/scanner is chowned explicitly: earlier layers (RustSec advisory-db
# clone) pre-create it as root, so useradd -m's own home-dir ownership is a
# no-op ("tolerates the home directory already existing" — it does not fix
# it). Without this, tools that lazily write their own dotfiles under $HOME
# at scan time (semgrep's ~/.semgrep, dotnet's ~/.dotnet first-run sentinel)
# fail with PermissionError even though every baked asset is present.
ENV CARGO_HOME=/home/scanner/.cargo
USER scanner
WORKDIR /src

# Gate the build on every tool actually running AS THE SCANNER USER. Building
# and pushing proves only that the layers assembled: both the semgrep $HOME
# regression (#455) and the dependency-check /opt/odc-data hang (#451) shipped
# green because nothing ever executed the image. ~3s, and it runs in CI for
# free since CI builds this same Dockerfile.
RUN python3 /opt/panopticon/scripts/smoke_adapters.py

ENTRYPOINT []
CMD ["semgrep", "--version"]
