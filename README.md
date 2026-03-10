# Code Scanner

Unified CLI-based security scanning system for orchestrating Gitleaks, Trivy, Semgrep, npm audit, and (for SCR) Horusec. Integrates with **AutoSecT** for SCR/SCA asset creation, scan runs, and report ingestion.

## Features

- Run multiple scanners in one command with unified reporting (includes CVE list per finding when available).
- **AutoSecT integration**: Create assets and scans in AutoSecT, then run scans locally via copied commands; vulnerabilities and reports appear in the respective scans in AutoSecT.

## Installation

```bash
npm install
npm run build
```

Ensure these tools are installed and available in `PATH`:

- **SCA:** `gitleaks`, `trivy`, `semgrep`, `npm`
- **SCR:** `horusec`

One-shot install (Ubuntu/macOS): `./scripts/install-scanner-tools.sh`

## Docker (run on any platform)

The image builds once (base + dependencies + app), then runs `run-scan-with-credentials.js` with the arguments you pass. Works on **Windows, macOS, and Linux** (x86_64 and ARM64). No need to install gitleaks, trivy, semgrep, npm, or horusec locally.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running

### Build

```bash
git clone <repo-url>
cd Autosect-codeScan
docker build -t code-scanner .
```

### Run (AutoSecT)

The Docker image works on macOS, Linux, and Windows, but the inside-container path you use is different by platform.

#### macOS/Linux

Use this flow if the copied command already contains a macOS/Linux path and you want to paste that same command inside the container.

1. Start the container and mount the host path to the **same absolute path** inside the container:

```bash
docker run --rm -it \
  -v <path of file or folder to scan>:<path of file or folder to scan> \
  --entrypoint bash \
  code-scanner
```

Example:

```bash
docker run --rm -it \
  -v /Users/admin/Desktop/DVWA:/Users/admin/Desktop/DVWA \
  --entrypoint bash \
  code-scanner
```

2. Go to the app folder:

```bash
cd /app
```

3. Paste and run the copied command:

```bash
node scripts/run-scan-with-credentials.js --scan-type scr --scan-id "<scan-id>" --token "<your-jwt>" --path /Users/admin/Desktop/DVWA --base-url https://autosect.threatcop.com
```

This works because the path in `--path` exists inside the container exactly as pasted.

#### Windows

Do **not** try to use the same Windows host path inside the Linux container. Instead, mount the folder to `/scan` and use `/scan` in the command inside the container.

1. Start the container:

```bash
docker run --rm -it \
  -v C:\Users\you\project:/scan \
  --entrypoint bash \
  code-scanner
```

2. Go to the app folder:

```bash
cd /app
```

3. Run the command with `/scan`:

```bash
node scripts/run-scan-with-credentials.js --scan-type scr --scan-id "<scan-id>" --token "<your-jwt>" --path /scan --base-url https://autosect.threatcop.com
```

For SCA, replace `--scan-type scr` with `--scan-type sca`.

If DNS fails (e.g. on corporate network), add `--dns 8.8.8.8 --dns 8.8.4.4` after `docker run --rm -it`.

## AutoSecT flow (SCR & SCA)

### Run scan from AutoSecT UI

1. **Log in to AutoSecT** — Open AutoSecT in your browser and sign in.
2. **Create an asset** — Create an **SCR** or **SCA** asset.
3. **Create a scan** — Create a scan for that asset and select the **Run locally**.
4. **Copy the command** — In the scan list, use the **copy** button beside the scan name to copy the run command.
5. **Run the scan** — Paste and run the copied command. **Without Docker:** use your real path for `--path`. **With Docker:** start the container with the same absolute path mounted, then run the copied `node scripts/run-scan-with-credentials.js ...` command inside the container with that same path in `--path`.
6. **View results** — After the scan completes, vulnerabilities and the report appear in the respective scan in AutoSecT.

**Example (SCR):**

```bash
node scripts/run-scan-with-credentials.js --scan-type scr --scan-id "<scan-id>" --token "<your-jwt>" --path /path/to/your/repo
```

**Example (SCA):**

```bash
node scripts/run-scan-with-credentials.js --scan-type sca --scan-id "<scan-id>" --token "<your-jwt>" --path /path/to/your/package-lock.json
```

Use the exact command from the copy button; only change `--path` to your target path.


