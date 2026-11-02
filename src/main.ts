import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import * as core from '@actions/core';
import { readCommitInfo } from './context.js';
import { findReports } from './find.js';
import { isInside, mapReportPaths, searchBases } from './paths.js';
import { readReportFiles } from './report.js';
import { failureReason, hasGitleaksIgnore, npmLockfileMissing, runGitleaks, runTrivy, trackedTree } from './scan.js';
import { scanPayload } from './scan-payload.js';
import { scanSummary, type ToolOutcome } from './summary.js';
import { installTool, runnerArch, TOOLS, type Arch, type ToolName } from './tools.js';
import { DEFAULT_API_URL, OIDC_AUDIENCE, sendCoverage, sendScan, type ScanPayload, type UploadReport } from './upload.js';

const FORMAT_LABEL = { lcov: 'LCOV', cobertura: 'Cobertura' } as const;

export async function run(): Promise<void> {
  const workspace = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  let scan = false;
  try {
    scan = core.getInput('scan') !== '' && core.getBooleanInput('scan');
  } catch {
    core.warning('scan must be true or false. The scan was skipped.');
  }
  const patterns = core
    .getMultilineInput('coverage-file')
    .flatMap((line) => line.split(','))
    .map((p) => p.trim())
    .filter(Boolean);
  if (patterns.length === 0 && !scan) {
    core.warning('Set coverage-file to the path of your LCOV or Cobertura XML report.');
    return;
  }
  if (patterns.length > 0) {
    try {
      await sendCoverageReports(patterns, workspace);
    } catch (err) {
      core.warning(`VibeDoctor step skipped: ${errorText(err)}`);
    }
  }
  if (scan) {
    try {
      await runScan(workspace);
    } catch (err) {
      core.warning(`VibeDoctor scan skipped: ${errorText(err)}`);
    }
  }
}

async function runScan(workspace: string): Promise<void> {
  const arch = runnerArch();
  if (!arch) {
    core.warning(`scan runs on Linux x64 and arm64 runners (this one is ${process.platform} ${process.arch}). The scan was skipped.`);
    return;
  }
  const dir = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'vibedoctor-scan-'));
  try {
    const tree = await trackedTree(workspace, path.join(dir, 'repo'));
    if (!tree) core.info("git could not list this checkout's files, so the scan reads the whole workspace, including files the job made.");
    const root = tree ?? workspace;
    const secrets = await runTool('gitleaks', arch, dir, (bin) => runGitleaks(bin, root, dir), (found) => found.length);
    const vulnerabilities = await runTool('trivy', arch, dir, (bin) => runTrivy(bin, root, dir), (report) => report.findings.length);
    const lockfileMissing = npmLockfileMissing(root);
    await core.summary.addRaw(scanSummary(secrets, vulnerabilities, { lockfileMissing })).write();
    await sendScanResults(scanPayload(readCommitInfo(process.env), secrets, vulnerabilities, { ignoreFile: hasGitleaksIgnore(root), lockfileMissing }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function runTool<R>(
  name: ToolName,
  arch: Arch,
  dir: string,
  scan: (binary: string) => Promise<R>,
  count: (result: R) => number,
): Promise<ToolOutcome<R>> {
  const label = `${name === 'gitleaks' ? 'Gitleaks' : 'Trivy'} ${TOOLS[name].version}`;
  try {
    const result = await scan(await installTool(name, arch, dir));
    const found = count(result);
    core.info(`${label}: ${found} ${found === 1 ? 'finding' : 'findings'}. See the job summary.`);
    return { ok: true, result };
  } catch (err) {
    const error = failureReason(err);
    core.warning(`${label} could not run: ${error}`);
    return { ok: false, error };
  }
}

async function sendScanResults(payload: ScanPayload): Promise<void> {
  let token: string;
  try {
    token = await core.getIDToken(OIDC_AUDIENCE);
  } catch (err) {
    core.info(`Scan results were not sent to VibeDoctor: no GitHub OIDC token (${errorText(err)}). Add "id-token: write" to the job's permissions to send them.`);
    return;
  }
  const result = await sendScan(core.getInput('api-url') || DEFAULT_API_URL, tokenSource(token), payload);
  core.info(result.message);
}

/** The server refuses a reused token, so each retry asks GitHub for a new one. */
function tokenSource(first: string): () => Promise<string> {
  let unused: string | null = first;
  return async () => {
    const next = unused ?? (await core.getIDToken(OIDC_AUDIENCE));
    unused = null;
    return next;
  };
}

async function sendCoverageReports(patterns: string[], workspace: string): Promise<void> {
  const reportFiles = await findReports(patterns, workspace);
  if (reportFiles.length === 0) {
    core.warning(`No coverage report matched ${patterns.join(', ')}. Check that the tests ran with coverage on.`);
    return;
  }

  const reports = reportFiles.map((file) => prepareReport(file, workspace)).filter((r) => r !== null);
  if (reports.length === 0) return;

  let token: string;
  try {
    token = await core.getIDToken(OIDC_AUDIENCE);
  } catch (err) {
    core.warning(
      `Could not get a GitHub OIDC token (${errorText(err)}). Check that the job has "id-token: write" in its permissions. Coverage was not sent.`,
    );
    return;
  }

  const result = await sendCoverage(core.getInput('api-url') || DEFAULT_API_URL, tokenSource(token), {
    version: 1,
    commit: readCommitInfo(process.env),
    reports,
  });
  if (result.sent) core.info(result.message);
  else core.warning(result.message);
}

function prepareReport(file: string, workspace: string): UploadReport | null {
  const name = isInside(file, workspace) ? path.relative(workspace, file).split(path.sep).join('/') : path.basename(file);
  const raw = fs.readFileSync(file);

  let parsed;
  try {
    parsed = readReportFiles(raw.toString('utf8'));
  } catch (err) {
    core.warning(`${name}: ${errorText(err)}. Skipped.`);
    return null;
  }

  if (parsed.files.length === 0) {
    core.warning(`${name}: the report lists no files. Skipped.`);
    return null;
  }

  const paths = mapReportPaths(parsed.files, searchBases(file, parsed.sources, workspace), workspace);
  const missing = parsed.files.filter((f) => !Object.hasOwn(paths, f));
  for (const f of missing) core.debug(`${name}: not found in the repository: ${f}`);
  const found = parsed.files.length - missing.length;
  if (found === 0) {
    core.warning(`${name}: none of its ${parsed.files.length} files are in this repository (for example ${missing[0]}). Skipped.`);
    return null;
  }

  core.info(`${name}: ${FORMAT_LABEL[parsed.format]}, ${found} of ${parsed.files.length} files found in the repository.`);
  return { name, format: parsed.format, paths, content: zlib.gzipSync(raw).toString('base64') };
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
