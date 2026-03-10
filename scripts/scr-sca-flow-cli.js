#!/usr/bin/env node
/**
 * CLI for SCR and SCA asset creation and scan flow.
 * Flow: 1) Authenticate (email/password)  2) Choose SCR or SCA  3) Create asset or pick existing  4) Initiate scan
 * SCR: runs Horusec via code-scanner CLI. SCA: runs gitleaks, trivy, semgrep, npm-audit via code-scanner CLI.
 *
 * Run: node scripts/scr-sca-flow-cli.js
 * Or: npm run scr-sca-flow
 * Or: BASE_URL=http://localhost:8080 node scripts/scr-sca-flow-cli.js
 * Or: AUTOSECT_BASE_URL=https://autosect.example.com node scripts/scr-sca-flow-cli.js
 */

import readline from "readline";
import fs from "fs";
import path from "path";
import os from "os";
import { spawn, execSync } from "child_process";
import { fileURLToPath, pathToFileURL } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const cliPath = path.join(projectRoot, "dist", "cli.js");

let rl = readline.createInterface({ input: process.stdin, output: process.stdout });

const prompt = (question, defaultVal) =>
  new Promise((resolve) => {
    const def = defaultVal !== undefined ? ` (${defaultVal})` : "";
    rl.question(`${question}${def}: `, (answer) => resolve((answer.trim() || defaultVal || "").trim()));
  });

/** Prompt for password with masked input (shows ******** only). */
function promptPassword(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const stdout = process.stdout;
    const isTTY = stdin.isTTY;
    const restoreEcho = () => {
      if (isTTY) {
        try {
          execSync("stty echo", { stdio: "ignore", encoding: "utf8" });
        } catch (_) {}
      }
    };
    rl.close();
    if (isTTY) {
      try {
        execSync("stty -echo", { stdio: "ignore", encoding: "utf8" });
      } catch (_) {}
    }
    stdout.write(`${question}: `);
    if (isTTY) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let password = "";
    const onData = (char) => {
      if (char === "\n" || char === "\r" || char === "\u0004") {
        stdin.removeListener("data", onData);
        if (isTTY) stdin.setRawMode(false);
        restoreEcho();
        stdout.write("\n");
        rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        resolve(password);
        return;
      }
      if (char === "\u0003") {
        if (isTTY) stdin.setRawMode(false);
        restoreEcho();
        rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        process.exit(130);
        return;
      }
      if (char === "\u007f" || char === "\b") {
        if (password.length > 0) {
          password = password.slice(0, -1);
          stdout.write("\b \b");
        }
        return;
      }
      password += char;
      stdout.write("*");
    };
    stdin.on("data", onData);
  });
}

const promptChoice = (question, choices) =>
  new Promise((resolve) => {
    const text = choices.map((c, i) => `${i + 1}) ${c}`).join("  ");
    rl.question(`${question}\n  ${text}\n  Choice: `, (answer) => {
      const n = parseInt(answer.trim(), 10);
      if (n >= 1 && n <= choices.length) resolve(choices[n - 1]);
      else resolve(choices[0]);
    });
  });

// Support both BASE_URL and AUTOSECT_BASE_URL (autosect endpoint)
const baseUrl = (process.env.AUTOSECT_BASE_URL || process.env.BASE_URL || "https://stag-autosect.threatcop.com").replace(/\/$/, "");
let token = null;
let user = null;

/** Error thrown when API indicates session expired / logged out; triggers re-login from main(). */
class AuthRequiredError extends Error {
  constructor(message = "Session expired or logged out.") {
    super(message);
    this.name = "AuthRequiredError";
    this.needReauth = true;
  }
}

function authHeaders() {
  if (!token) throw new Error("Not authenticated. Run login first.");
  return { Cookie: `jwt=${token}` };
}

async function login() {
  console.log("\n--- Authentication ---");
  const email = await prompt("Email");
  const password = await promptPassword("Password");
  if (!email || !password) {
    throw new Error("Email and password are required.");
  }
  const res = await fetch(`${baseUrl}/api/user/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!data.success || !data.token) {
    throw new Error(data.messages || "Login failed.");
  }
  token = data.token;
  user = data.user;
  console.log(`Logged in as ${user.name} (${user.email}).\n`);
  return { token, user };
}

// ---------- SCR ----------
async function createScrAsset(assetName, filePath) {
  const form = new FormData();
  form.append("name", assetName);
  if (user?._id && user?.name) {
    form.append("creator", JSON.stringify({ id: user._id, name: user.name }));
  }
  if (filePath) {
    const fullPath = path.resolve(filePath);
    if (!fs.existsSync(fullPath)) throw new Error(`File not found: ${fullPath}`);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      console.log("(Skipping upload: path is a directory; use it when asked for 'Path to source'.)");
    } else {
      const buf = fs.readFileSync(fullPath);
      form.append("file", new Blob([buf]), path.basename(fullPath));
    }
  }
  const res = await fetch(`${baseUrl}/api/scrasset/create-scrasset`, {
    method: "POST",
    headers: authHeaders(),
    body: form,
  });
  const data = await res.json();
  if (!data.success || !data.assetId) {
    throw new Error(data.messages || "Create SCR asset failed.");
  }
  console.log(`SCR asset created: ${data.assetId}`);
  return { assetId: data.assetId, assetName };
}

async function initiateScrScan(assetId, assetName, scanName, scanMethod, runLocally = true) {
  const url = `${baseUrl}/api/scrasset/create-scr-scan`;
  console.log("[SCR] Creating scan:", url);
  const form = new FormData();
  form.append("asset", JSON.stringify({ id: assetId, name: assetName, type: "SCR" }));
  form.append("name", scanName);
  form.append("scanMethod", scanMethod);
  form.append("runLocally", String(runLocally ?? true));
  let res;
  try {
    res = await fetch(url, { method: "POST", headers: authHeaders(), body: form });
  } catch (err) {
    console.error("[SCR] create-scr-scan fetch error:", err.message);
    if (err.cause) console.error("[SCR] cause:", err.cause.message || err.cause);
    throw err;
  }
  const raw = await res.text();
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    console.error("[SCR] create-scr-scan non-JSON response:", res.status, raw?.slice(0, 200));
    throw new Error(`Create SCR scan failed: ${res.status} ${res.statusText}`);
  }
  if (!data.success) {
    console.error("[SCR] create-scr-scan API error:", res.status, data);
    throw new Error(data.messages || data.message || "Create SCR scan failed.");
  }
  console.log("[SCR] Scan created successfully. scanId:", data.scanId ?? "(none in response)");
  return data;
}

/** POST to save-vul-scr; body: { scanId, vulnerabilities }. API expects "vulnerabilities", not "findings". */
async function saveScrVulns(scanId, findings) {
  const url = `${baseUrl}/api/scrasset/save-vul-scr`;
  const vulnerabilities = Array.isArray(findings) ? findings : [];
  const count = vulnerabilities.length;
  console.log("[SCR] Saving to API:", url, "scanId:", scanId, "vulnerabilities:", count);
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ scanId, vulnerabilities }),
    });
  } catch (err) {
    console.error("[SCR] save-vul-scr fetch error:", err.message);
    if (err.cause) console.error("[SCR] cause:", err.cause.message || err.cause);
    throw err;
  }
  const raw = await res.text();
  let data;
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    console.error("[SCR] save-vul-scr non-JSON response:", res.status, res.statusText, raw?.slice(0, 300));
    throw new Error(`Save SCR vulnerabilities failed: ${res.status} ${res.statusText}`);
  }
  if (!res.ok || !data.success) {
    console.error("[SCR] save-vul-scr API error:", res.status, data);
    throw new Error(data.message || data.messages || "Save SCR vulnerabilities failed.");
  }
  // API returns: { success, message, savedCount, scanName }
  console.log("[SCR]", data.message ?? "Findings saved successfully.");
  if (data.savedCount != null) console.log("[SCR] savedCount:", data.savedCount);
  if (data.scanName) console.log("[SCR] scanName:", data.scanName);
  return data;
}

// ---------- SCA ----------
async function createScaAsset(assetName, filePath) {
  const form = new FormData();
  form.append("name", assetName);
  if (user?._id && user?.name) {
    form.append("creator", JSON.stringify({ id: user._id, name: user.name }));
  }
  if (filePath) {
    const fullPath = path.resolve(filePath);
    if (!fs.existsSync(fullPath)) throw new Error(`File not found: ${fullPath}`);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      console.log("(Skipping upload: path is a directory; use it when asked for 'Path to source'.)");
    } else {
      const buf = fs.readFileSync(fullPath);
      form.append("file", new Blob([buf]), path.basename(fullPath));
    }
  }
  const res = await fetch(`${baseUrl}/api/sca/create-scaasset`, {
    method: "POST",
    headers: authHeaders(),
    body: form,
  });
  const data = await res.json();
  if (!data.success || !data.assetId) {
    throw new Error(data.messages || "Create SCA asset failed.");
  }
  console.log(`SCA asset created: ${data.assetId}`);
  return { assetId: data.assetId, assetName };
}

async function initiateScaScan(assetId, assetName, scanName, scanMethod, runLocally = true) {
  const body = {
    asset: { id: assetId, name: assetName, type: "SCA" },
    name: scanName,
    scanMethod,
    runLocally: runLocally ?? true,
  };
  const res = await fetch(`${baseUrl}/api/sca/create-sca-scan`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!data.success) {
    throw new Error(data.messages || "Create SCA scan failed.");
  }
  console.log(runLocally ? "SCA scan created (run locally)." : "SCA scan initiated successfully.");
  return data;
}

// ---------- Run code-scanner CLI ----------
async function extractZipToTemp(zipPath) {
  const resolved = path.resolve(zipPath);
  if (!fs.existsSync(resolved)) throw new Error(`Zip not found: ${resolved}`);
  const tempDir = path.join(os.tmpdir(), `scr-sca-scan-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`);
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

/** Run code-scanner with JSON output; returns report object { findings, summary } for ingest. */
function runCodeScannerWithJsonReport(tools, scanPath, cleanupTempDir = null, options = {}) {
  const { quiet = false } = options;
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(cliPath)) {
      reject(new Error("Code-scanner not built. Run: npm run build"));
      return;
    }
    const toolsArg = Array.isArray(tools) ? tools.join(",") : tools;
    const outFile = path.join(os.tmpdir(), `sca-report-${Date.now()}-${Math.random().toString(36).slice(2, 9)}.json`);
    const args = ["scan", scanPath, "--tools", toolsArg, "--format", "json", "--output", outFile];
    if (quiet) args.push("--quiet");
    console.log("Scan in progress...");
    const proc = spawn("node", [cliPath, ...args], {
      cwd: projectRoot,
      stdio: ["inherit", "pipe", "pipe"],
      shell: false,
    });
    proc.stdout?.on("data", () => {});
    proc.stderr?.on("data", () => {});
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
        reject(new Error(`Scan exited with code ${code}`));
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

/** Generate HTML report from code-scanner report (uses dist/reporters). */
async function reportToHtml(report) {
  const reportersPath = pathToFileURL(path.join(projectRoot, "dist", "reporters", "index.js")).href;
  const { formatReport } = await import(reportersPath);
  return formatReport(report, "html");
}

/** Save report HTML to autosect backend public folder (no S3 creds needed on client). */
async function saveReportToAutosect(scanId, reportHtml) {
  const res = await fetch(`${baseUrl}/api/sca/upload-scan-report`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, reportHtml }),
  });
  const data = await res.json();
  if (!res.ok || !data.success) {
    throw new Error(data.message || data.messages || "Save report failed.");
  }
  return data;
}

async function ingestScaReport(scanId, report) {
  const res = await fetch(`${baseUrl}/api/sca/ingest-report`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, report }),
  });
  const data = await res.json();
  if (!res.ok || !data.success) {
    throw new Error(data.message || data.messages || "Ingest report failed.");
  }
  return data;
}

// ---------- Main ----------
async function promptAfterScan() {
  const choice = await promptChoice("What next?", [
    "Create new asset and scan again",
    "Exit",
  ]);
  return choice === "Exit";
}

const MAX_ASSET_CREATE_ATTEMPTS = 3;

/** One round: create SCR asset, optionally initiate scan and run Horusec. */
async function runScrFlowOnce() {
  let result;
  let assetFilePath = "";

  for (let attempt = 1; attempt <= MAX_ASSET_CREATE_ATTEMPTS; attempt++) {
    const assetName = await prompt("SCR asset name");
    if (!assetName) throw new Error("Asset name is required.");
    const filePath = await prompt("Path to file to scan");
    assetFilePath = (filePath || "").trim();
    if (!assetFilePath) throw new Error("Path to file is required.");

    try {
      result = await createScrAsset(assetName, assetFilePath);
      break;
    } catch (err) {
      if (err instanceof AuthRequiredError || err.needReauth) throw err;
      console.error(`Create SCR asset failed (attempt ${attempt}/${MAX_ASSET_CREATE_ATTEMPTS}):`, err.message);
      if (attempt >= MAX_ASSET_CREATE_ATTEMPTS) {
        console.error("Max attempts reached. Breaking pipeline.");
        return;
      }
      console.log("Please enter a different asset name and/or path to try again.\n");
    }
  }
  const { assetId, assetName: name } = result;

  const startScan = await promptChoice("Initiate scan for this asset?", ["Yes", "No"]);
  if (startScan !== "Yes") {
    console.log("Done. No scan started.");
    return;
  }

  const scanName = await prompt("Scan name", `Scan-${Date.now()}`);
  const createScanRes = await initiateScrScan(assetId, name, scanName, "Automated", true);
    const scanId = createScanRes.scanId;
    console.log("[SCR] scanId for this run:", scanId ?? "(missing – API may not return scanId)");

    const pathPrompt = await prompt("Path to source (directory or .zip) to scan with Horusec", assetFilePath ?? "");
    if (pathPrompt) {
      try {
        console.log("[SCR] Resolving path:", pathPrompt);
        const { scanPath, cleanupTempDir } = await resolveScanPath(pathPrompt);
        console.log("[SCR] Scan path:", scanPath, "cleanupTempDir:", cleanupTempDir ?? "none");
        console.log("[SCR] Running Horusec (code-scanner with JSON report)...");
        const report = await runCodeScannerWithJsonReport(["horusec"], scanPath, cleanupTempDir, { quiet: true });
        const findingsCount = report?.findings?.length ?? 0;
        console.log("[SCR] Horusec finished. Findings count:", findingsCount);
        if (scanId) {
          try {
            await saveScrVulns(scanId, report.findings ?? []);
            console.log(`Scan completed – ${scanName}. Findings saved to autosect.`);
          } catch (apiErr) {
            const msg = apiErr.message || String(apiErr);
            const cause = apiErr.cause ? ` (${apiErr.cause.message || apiErr.cause})` : "";
            console.error(`[SCR] Save to API failed: ${msg}${cause}`);
            if (apiErr.cause) console.error("[SCR] cause detail:", apiErr.cause);
            console.error("[SCR] API base URL:", baseUrl, "– ensure the server is running and reachable.");
          }
        } else {
          console.log(`Scan completed – ${scanName}. (No scanId returned; findings not sent to API.)`);
        }
      } catch (e) {
        console.error("[SCR] Error:", e.message);
        if (e.cause) console.error("[SCR] cause:", e.cause.message || e.cause);
        if (e.stack) console.error("[SCR] stack:", e.stack);
      }
    } else {
      console.log("\nDone. SCR scan created on server; run the scan worker to process it, or re-run and provide a path to run Horusec locally.");
    }
}

/** One round: create SCA asset, optionally initiate scan and run SCA tools + ingest. */
async function runScaFlowOnce() {
  let result;
  let assetFilePath = "";

  for (let attempt = 1; attempt <= MAX_ASSET_CREATE_ATTEMPTS; attempt++) {
    const assetName = await prompt("SCA asset name");
    if (!assetName) throw new Error("Asset name is required.");
    const filePath = await prompt("Path to file to scan");
    assetFilePath = (filePath || "").trim();
    if (!assetFilePath) throw new Error("Path to file is required.");

    try {
      result = await createScaAsset(assetName, assetFilePath);
      break;
    } catch (err) {
      if (err instanceof AuthRequiredError || err.needReauth) throw err;
      console.error(`Create SCA asset failed (attempt ${attempt}/${MAX_ASSET_CREATE_ATTEMPTS}):`, err.message);
      if (attempt >= MAX_ASSET_CREATE_ATTEMPTS) {
        console.error("Max attempts reached. Breaking pipeline.");
        return;
      }
      console.log("Please enter a different asset name and/or path to try again.\n");
    }
  }
  const { assetId, assetName: name } = result;

  const startScan = await promptChoice("Initiate scan for this asset?", ["Yes", "No"]);
  if (startScan !== "Yes") {
    console.log("Done. No scan started.");
    return;
  }

  const scanName = await prompt("Scan name", `Scan-${Date.now()}`);
  const createRes = await initiateScaScan(assetId, name, scanName, "Automated", true);
  const scanId = createRes.scanId;

  const pathPrompt = await prompt("Path to source to scan", assetFilePath);
  if (pathPrompt && scanId) {
    try {
      const { scanPath, cleanupTempDir } = await resolveScanPath(pathPrompt);
      const report = await runCodeScannerWithJsonReport(["gitleaks", "trivy", "semgrep", "npm-audit"], scanPath, cleanupTempDir, { quiet: true });
      const reportHtml = await reportToHtml(report);
      await saveReportToAutosect(scanId, reportHtml);
      await ingestScaReport(scanId, report);
      console.log(`Scan completed – ${scanName}. See your report in autosect.`);
    } catch (e) {
      console.error("SCA scan or ingest failed:", e.message);
    }
  } else if (!pathPrompt) {
    console.log("\nDone. SCA scan created (run locally)");
  }
}

async function main() {
  console.log("SCR & SCA Asset & Scan CLI");
  console.log(`API base: ${baseUrl}\n`);

  try {
    await login();

    while (true) {
      const assetType = await promptChoice("Choose asset type", ["SCR", "SCA"]);

      if (assetType === "SCR") {
        await runScrFlowOnce();
      } else {
        await runScaFlowOnce();
      }

      if (await promptAfterScan()) break;
    }
  } catch (err) {
    const msg = err.messages ?? err.message ?? String(err);
    console.error(Array.isArray(msg) ? msg.join("; ") : msg);
    process.exit(1);
  } finally {
    rl.close();
  }
}

main();
