#!/usr/bin/env node
/**
 * Run a scan and push results to AutoSecT using existing scanId and JWT token (or API key).
 * No login, asset creation, or scan creation – provide scanId, token, path, and scan type.
 * Auth: sends JWT (or API key) via Authorization: Bearer and x-api-key (backend can validate either).
 *
 * Usage:
 *   node scripts/run-scan-with-credentials.js --scan-type scr --scan-id <id> --token <jwt> --path <path>
 *   node scripts/run-scan-with-credentials.js --scan-type sca --scan-id <id> --token <jwt> --path <path>
 *
 * Options:
 *   --scan-type   scr | sca   (required)
 *   --scan-id     Scan ID from the already-created scan (required)
 *   --token       JWT token or API key for API auth (required). Also accepted: --api-key (same as --token)
 *   --path        Path to scan: directory, .zip, or file (required)
 *   --base-url    API base URL (optional; else AUTOSECT_BASE_URL or BASE_URL or default)
 *
 * SCR: runs CodeQL, then POSTs findings to /api/scrasset/save-vul-scr.
 * SCA: runs gitleaks, trivy, semgrep, npm-audit; uploads HTML report and ingests to AutoSecT.
 */

import fs from "fs";
import path from "path";
import os from "os";
import { spawn } from "child_process";
import { fileURLToPath, pathToFileURL } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const cliPath = path.join(projectRoot, "dist", "cli.js");

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { scanType: null, scanId: null, apiKey: null, path: null, baseUrl: null, commit: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--scan-type" && args[i + 1]) {
      out.scanType = args[++i].toLowerCase();
    } else if (args[i] === "--scan-id" && args[i + 1]) {
      out.scanId = args[++i];
    } else if ((args[i] === "--api-key" || args[i] === "--token") && args[i + 1]) {
      out.apiKey = args[++i];
    } else if ((args[i] === "--path" || args[i] === "--file-path") && args[i + 1]) {
      out.path = args[++i].trim();
    } else if (args[i] === "--commit" && args[i + 1]) {
      out.commit = args[++i];
    } else if (args[i] === "--base-url" && args[i + 1]) {
      out.baseUrl = args[++i].replace(/\/$/, "");
    }
  }
  return out;
}

const baseUrlFromEnv = (process.env.AUTOSECT_BASE_URL || process.env.BASE_URL || "https://autosect.threatcop.com").replace(/\/$/, "");

/** Send JWT token (or API key) as Bearer + x-api-key (matches getApiKeyFromRequest on backend). */
function authHeaders(token) {
  if (!token) throw new Error("JWT token or API key is required (use --token or --api-key).");
  return {
    Authorization: `Bearer ${token}`,
    "x-api-key": token,
  };
}

async function extractZipToTemp(zipPath) {
  const resolved = path.resolve(zipPath);
  if (!fs.existsSync(resolved)) throw new Error(`Zip not found: ${resolved}`);
  const tempDir = path.join(os.tmpdir(), `run-scan-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`);
  fs.mkdirSync(tempDir, { recursive: true });
  const AdmZip = (await import("adm-zip")).default;
  const zip = new AdmZip(resolved);
  zip.extractAllTo(tempDir, true);
  return tempDir;
}

async function resolveScanPath(userPath) {
  if (!userPath || !userPath.trim()) throw new Error("Path is required.");
  const p = path.resolve(userPath.trim());
  if (!fs.existsSync(p)) throw new Error(`Path not found: ${p}`);
  const stat = fs.statSync(p);
  if (stat.isDirectory()) return { scanPath: p, cleanupTempDir: null };
  if (stat.isFile() && p.toLowerCase().endsWith(".zip")) {
    console.log("Extracting zip to temp directory...");
    const tempDir = await extractZipToTemp(p);
    return { scanPath: tempDir, cleanupTempDir: tempDir };
  }
  return { scanPath: p, cleanupTempDir: null };
}

function runCodeScannerWithJsonReport(tools, scanPath, cleanupTempDir, options = {}) {
  const { quiet = true } = options;
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(cliPath)) {
      reject(new Error("Code-scanner not built. Run: npm run build"));
      return;
    }
    const outFile = path.join(os.tmpdir(), `scan-report-${Date.now()}-${Math.random().toString(36).slice(2, 9)}.json`);
    const args = ["scan", scanPath, "--format", "json", "--output", outFile];
    const toolsArg = Array.isArray(tools) ? tools.join(",") : tools;
    if (toolsArg) args.push("--tools", toolsArg);
    if (options.commit) args.push("--commit", options.commit);
    if (quiet) args.push("--quiet");
    console.log("Scan in progress...");
    const proc = spawn("node", [cliPath, ...args], {
      cwd: projectRoot,
      stdio: ["inherit", "pipe", "pipe"],
      shell: false,
    });
    const stderrChunks = [];
    proc.stdout?.on("data", () => {});
    proc.stderr?.on("data", (chunk) => { stderrChunks.push(chunk); });
    proc.on("close", (code) => {
      const cleanup = () => {
        if (cleanupTempDir) {
          try {
            fs.rmSync(cleanupTempDir, { recursive: true });
          } catch (_) {}
        }
        try {
          if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
        } catch (_) {}
      };
      if (code !== 0) {
        cleanup();
        const stderrText = Buffer.concat(stderrChunks).toString().trim();
        reject(new Error(stderrText || `Scan exited with code ${code}`));
        return;
      }
      try {
        const raw = fs.readFileSync(outFile, "utf8");
        const report = JSON.parse(raw);
        cleanup();
        resolve(report);
      } catch (e) {
        cleanup();
        reject(new Error(`Failed to read report: ${e.message}`));
      }
    });
    proc.on("error", (err) => reject(err));
  });
}

async function saveScrVulns(baseUrl, apiKey, scanId, findings) {
  const url = `${baseUrl}/api/scrasset/save-vul-scr`;
  const vulnerabilities = Array.isArray(findings) ? findings : [];
  console.log("[SCR] Saving to API:", "scanId:", scanId, "vulnerabilities:", vulnerabilities.length);
  const res = await fetch(url, {
    method: "POST",
    headers: { ...authHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, vulnerabilities }),
  });
  const raw = await res.text();
  const data = raw ? JSON.parse(raw) : {};
  if (!res.ok || !data.success) {
    throw new Error(data.message || data.messages || "Save SCR vulnerabilities failed.");
  }
  console.log("[SCR]", data.message ?? "Findings saved successfully.");
  if (data.savedCount != null) console.log("[SCR] savedCount:", data.savedCount);
  return data;
}

async function reportToHtml(report) {
  const reportersPath = pathToFileURL(path.join(projectRoot, "dist", "reporters", "index.js")).href;
  const { formatReport } = await import(reportersPath);
  return formatReport(report, "html");
}

async function saveReportToAutosect(baseUrl, apiKey, scanId, reportHtml) {
  const res = await fetch(`${baseUrl}/api/sca/upload-scan-report`, {
    method: "POST",
    headers: { ...authHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, reportHtml }),
  });
  const data = await res.json();
  if (!res.ok || !data.success) {
    throw new Error(data.message || data.messages || "Save report failed.");
  }
  return data;
}

async function ingestScaReport(baseUrl, apiKey, scanId, report) {
  const res = await fetch(`${baseUrl}/api/sca/ingest-report`, {
    method: "POST",
    headers: { ...authHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, report }),
  });
  const data = await res.json();
  if (!res.ok || !data.success) {
    throw new Error(data.message || data.messages || "Ingest report failed.");
  }
  return data;
}

async function runScr(baseUrl, apiKey, scanId, filePath, commit) {
  console.log("[SCR] Resolving path:", filePath);
  const { scanPath, cleanupTempDir } = await resolveScanPath(filePath);
  console.log("[SCR] Scan path:", scanPath);
  const report = await runCodeScannerWithJsonReport(["codeql","horusec"], scanPath, cleanupTempDir, { quiet: false, commit });
  const count = report?.findings?.length ?? 0;
  console.log("[SCR] CodeQL and Horusec finished. Findings count:", count);
  await saveScrVulns(baseUrl, apiKey, scanId, report.findings ?? []);
  console.log("SCR scan completed. Findings saved to AutoSecT.");
}

async function runSca(baseUrl, apiKey, scanId, filePath, commit) {
  console.log("[SCA] Resolving path:", filePath);
  const { scanPath, cleanupTempDir } = await resolveScanPath(filePath);
  console.log("[SCA] Scan path:", scanPath);
  const report = await runCodeScannerWithJsonReport(null, scanPath, cleanupTempDir, { quiet: false, commit });
  const localFindingsCount = report?.findings?.length ?? 0;
  console.log("[SCA] Local findings count:", localFindingsCount);
  const reportHtml = await reportToHtml(report);
  await saveReportToAutosect(baseUrl, apiKey, scanId, reportHtml);
  await ingestScaReport(baseUrl, apiKey, scanId, report);
  console.log("SCA scan completed. Report uploaded and vulnerabilities ingested to AutoSecT.");
}

async function main() {
  const { scanType, scanId, apiKey, path: filePath, baseUrl, commit } = parseArgs();
  const base = baseUrl || baseUrlFromEnv;

  const missing = [];
  if (!scanType || !["scr", "sca"].includes(scanType)) {
    missing.push("--scan-type (scr or sca)");
  }
  if (!scanId) missing.push("--scan-id");
  if (!apiKey) missing.push("--token or --api-key");
  if (!filePath) missing.push("--path");

  if (missing.length) {
    console.error("Missing required option(s): " + missing.join(", "));
    console.error("");
    console.error("Usage:");
    console.error("  node scripts/run-scan-with-credentials.js --scan-type scr|sca --scan-id <id> --token <jwt> --path <path>");
    console.error("");
    console.error("Required:");
    console.error("  --scan-type   scr | sca");
    console.error("  --scan-id     Scan ID from the already-created scan");
    console.error("  --token       JWT token or API key (or use --api-key)");
    console.error("  --path        Path to scan (directory, .zip, or file)");
    console.error("");
    console.error("Optional:");
    console.error("  --base-url    API base URL (default: env AUTOSECT_BASE_URL or BASE_URL)");
    process.exit(1);
  }

  console.log("Run scan with credentials");
  console.log("  scan-type:", scanType);
  console.log("  scan-id:", scanId);
  console.log("  path:", filePath);
  console.log("  base-url:", base);
  if (commit) console.log("  commit:", commit);
  console.log("");

  try {
    if (scanType === "scr") {
      await runScr(base, apiKey, scanId, filePath, commit);
    } else {
      await runSca(base, apiKey, scanId, filePath, commit);
    }
  } catch (err) {
    console.error(err.message || err);
    process.exit(1);
  }
}

main();
