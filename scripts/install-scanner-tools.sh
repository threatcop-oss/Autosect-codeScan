#!/usr/bin/env bash
#
# Install SCA/SCR scanner tools in one go: gitleaks, trivy, semgrep, npm (Node), horusec.
# Supports Ubuntu/Linux and macOS.
# Usage: ./scripts/install-scanner-tools.sh   or   bash scripts/install-scanner-tools.sh
#
set -e

OS="$(uname -s)"
ARCH="$(uname -m)"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SUDO="${SUDO:-sudo}"

echo "=== Install scanner tools (OS: $OS, ARCH: $ARCH) ==="

# ----- Node / npm -----
install_node() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    echo "[ok] Node $(node -v) and npm $(npm -v) already installed."
    return 0
  fi
  if [ "$OS" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      echo "Installing Node via Homebrew..."
      brew install node
    else
      echo "Install Homebrew (https://brew.sh) and run: brew install node"
      return 1
    fi
  else
    echo "Node/npm not found. Install Node.js (e.g. nvm or https://nodejs.org) and re-run."
    return 1
  fi
}

# ----- Gitleaks -----
install_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1; then
    echo "[ok] Gitleaks already installed: $(gitleaks version 2>/dev/null || true)"
    return 0
  fi
  if [ "$OS" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      brew install gitleaks
    else
      echo "Install Homebrew to get gitleaks, or install manually from https://github.com/gitleaks/gitleaks/releases"
      return 1
    fi
  else
    echo "Installing Gitleaks..."
    GITLEAKS_VERSION=$(curl -s "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    [ -z "$GITLEAKS_VERSION" ] && { echo "Could not get Gitleaks version"; return 1; }
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
      GITLEAKS_ARCH="linux_x64"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
      GITLEAKS_ARCH="linux_arm64"
    else
      echo "Unsupported arch for gitleaks: $ARCH"
      return 1
    fi
    wget -qO /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz"
    $SUDO tar xf /tmp/gitleaks.tar.gz -C "$BIN_DIR" gitleaks
    rm -f /tmp/gitleaks.tar.gz
  fi
  gitleaks version
}

# ----- Trivy -----
install_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    echo "[ok] Trivy already installed: $(trivy --version 2>/dev/null | head -1 || true)"
    return 0
  fi
  if [ "$OS" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      brew install trivy
    else
      echo "Install Homebrew to get trivy."
      return 1
    fi
  else
    echo "Installing Trivy..."
    TRIVY_VERSION=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    [ -z "$TRIVY_VERSION" ] && { echo "Could not get Trivy version"; return 1; }
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
      TRIVY_ARCH="Linux-64bit"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
      TRIVY_ARCH="Linux-ARM64"
    else
      echo "Unsupported arch for trivy: $ARCH"
      return 1
    fi
    wget -qO /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz"
    $SUDO tar xf /tmp/trivy.tar.gz -C "$BIN_DIR" trivy
    rm -f /tmp/trivy.tar.gz
  fi
  trivy --version
}

# ----- Semgrep -----
install_semgrep() {
  if command -v semgrep >/dev/null 2>&1; then
    echo "[ok] Semgrep already installed: $(semgrep --version 2>/dev/null | head -1 || true)"
    return 0
  fi
  if [ "$OS" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    brew install semgrep
  elif command -v pip3 >/dev/null 2>&1; then
    echo "Installing Semgrep via pip3..."
    pip3 install semgrep
  else
    echo "Install Python 3 and pip3, or on macOS: brew install semgrep"
    return 1
  fi
  semgrep --version
}

# ----- Horusec -----
install_horusec() {
  if command -v horusec >/dev/null 2>&1; then
    echo "[ok] Horusec already installed: $(horusec version 2>/dev/null || true)"
    return 0
  fi
  echo "Installing Horusec..."
  curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/master/deployments/scripts/install.sh | bash -s latest
  horusec version
}

# ----- Main -----
install_node    || true
install_gitleaks || true
install_trivy   || true
install_semgrep || true
install_horusec || true

echo ""
echo "=== Verify ==="
for cmd in node npm gitleaks trivy semgrep horusec; do
  if command -v "$cmd" >/dev/null 2>&1; then
    v="$($cmd --version 2>&1)" || v="$($cmd version 2>&1)" || v="ok"
    echo "  $cmd: $(echo "$v" | head -1)"
  else
    echo "  $cmd: not found"
  fi
done
echo ""
echo "Done."
