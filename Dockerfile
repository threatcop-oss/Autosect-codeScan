# Code Scanner - runs run-scan-with-credentials.js (SCR/SCA → AutoSecT)
# Flow: (1) Initialize base image (2) Install all dependencies (3) Copy app & build (4) Run script with your args

# --- 1. Initialize ---
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# --- 2. Install all dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget gnupg python3 python3-pip git jq sudo \
    && rm -rf /var/lib/apt/lists/*

# Node.js 20 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Scanner tools (Gitleaks, Trivy, Semgrep, Horusec)
ARG GITLEAKS_VERSION=8.30.0
ARG TRIVY_VERSION=0.69.3
RUN ARCH=$(dpkg --print-architecture) \
    && GITLEAKS_ARCH=$([ "$ARCH" = "amd64" ] && echo "linux_x64" || echo "linux_arm64") \
    && wget -qO /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" \
    && tar xf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tar.gz && chmod +x /usr/local/bin/gitleaks
RUN ARCH=$(dpkg --print-architecture) \
    && TRIVY_ARCH=$([ "$ARCH" = "amd64" ] && echo "Linux-64bit" || echo "Linux-ARM64") \
    && curl -fL --retry 5 --retry-delay 2 --retry-all-errors -o /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
    && tar xf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && chmod +x /usr/local/bin/trivy
RUN pip3 install --no-cache-dir semgrep
RUN curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash -s latest

# --- 3. App: copy, install, build ---
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build && npm prune --omit=dev

# --- 4. Run script with your args (e.g. --scan-type sca --scan-id "..." --token "..." --path /scan) ---
ENTRYPOINT ["node", "scripts/run-scan-with-credentials.js"]
CMD []
