import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface SecretFinding {
  rule: string;
  description: string;
  file: string;
  line: number;
}

export interface VulnerabilityFinding {
  id: string;
  severity: string;
  pkg: string;
  installed: string;
  fixed: string | null;
  title: string;
  /** The lockfile or manifest it was found in. */
  target: string;
}

export interface TrivyReport {
  findings: VulnerabilityFinding[];
  checked: string[];
}

const TOOL_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_TOOL_OUTPUT = 10 * 1024 * 1024;
const MAX_GIT_LIST_OUTPUT = 256 * 1024 * 1024;
export const TRIVY_SKIP_DIRS = ['**/node_modules/**', '**/tests/fixtures/**', '**/test/fixtures/**'];
export const TRIVY_SEVERITIES = 'CRITICAL,HIGH,MEDIUM,LOW';
/** Since Trivy 0.71 a Maven Central 429 fails the whole run, so it runs again offline. */
const MAVEN_RATE_LIMITED_RE = /Maven repository returned 429/;
const NPM_LOCKFILES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lock'];

const text = (value: unknown) => (typeof value === 'string' ? value : '');

/** The tool's own last error line: Node's message for a failed command only repeats the command. */
export function failureReason(err: unknown): string {
  const { stderr, killed, cause, message } = (err ?? {}) as { stderr?: unknown; killed?: unknown; cause?: unknown; message?: unknown };
  if (killed === true) return `it did not finish within ${TOOL_TIMEOUT_MS / 60_000} minutes`;
  const lastLine = text(stderr).split('\n').map((l) => l.trim()).filter(Boolean).at(-1);
  const reason = lastLine ?? (cause instanceof Error ? `${text(message)} (${cause.message})` : text(message) || String(err));
  return reason.slice(0, 300);
}

/** Hard links to the files git tracks, so build output and virtualenvs are not scanned; null without git. */
export async function trackedTree(workspace: string, dest: string): Promise<string | null> {
  let listed: string;
  try {
    ({ stdout: listed } = await execFileAsync('git', ['ls-files', '-z'], { cwd: workspace, maxBuffer: MAX_GIT_LIST_OUTPUT }));
  } catch {
    return null;
  }
  linkFiles(workspace, listed.split('\0').filter(Boolean), dest);
  return dest;
}

/** Symlinks, submodules and files missing from the checkout are left out. */
export function linkFiles(workspace: string, files: string[], dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  const made = new Set<string>([dest]);
  for (const file of files) {
    const from = path.join(workspace, file);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(from);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;
    const to = path.join(dest, file);
    const parent = path.dirname(to);
    if (!made.has(parent)) {
      fs.mkdirSync(parent, { recursive: true });
      made.add(parent);
    }
    try {
      fs.linkSync(from, to);
    } catch {
      fs.copyFileSync(from, to);
    }
  }
}

/** Keeps no secret, match or line text from the report. */
export function readGitleaksReport(json: string): SecretFinding[] {
  const parsed = JSON.parse(json) as unknown;
  if (!Array.isArray(parsed)) throw new Error('Gitleaks wrote a report that is not a list');
  return parsed.map((f: Record<string, unknown>) => ({
    rule: text(f.RuleID),
    description: text(f.Description),
    file: text(f.File),
    line: typeof f.StartLine === 'number' ? f.StartLine : 0,
  }));
}

export function readTrivyReport(json: string): TrivyReport {
  const parsed = JSON.parse(json) as { Results?: Array<{ Target?: unknown; Class?: unknown; Vulnerabilities?: Array<Record<string, unknown>> | null }> };
  const results = parsed.Results ?? [];
  return {
    findings: results.flatMap((result) => (result.Vulnerabilities ?? []).map((v) => ({
      id: text(v.VulnerabilityID),
      severity: text(v.Severity) || 'UNKNOWN',
      pkg: text(v.PkgName),
      installed: text(v.InstalledVersion),
      fixed: text(v.FixedVersion) || null,
      title: text(v.Title),
      target: text(result.Target),
    }))),
    checked: [...new Set(results.filter((r) => r.Class === 'lang-pkgs').map((r) => text(r.Target)).filter(Boolean))],
  };
}

export function hasGitleaksIgnore(root: string): boolean {
  return fs.existsSync(path.join(root, '.gitleaksignore'));
}

export async function runGitleaks(binary: string, root: string, outDir: string): Promise<SecretFinding[]> {
  const report = path.join(outDir, 'gitleaks.json');
  const args = ['dir', '.', '--redact', '--report-format', 'json', '--report-path', report, '--no-banner', '--exit-code', '0'];
  if (hasGitleaksIgnore(root)) args.push('--gitleaks-ignore-path', path.join(root, '.gitleaksignore'));
  await execFileAsync(binary, args, { cwd: root, timeout: TOOL_TIMEOUT_MS, maxBuffer: MAX_TOOL_OUTPUT });
  return readGitleaksReport(await fs.promises.readFile(report, 'utf8'));
}

/** Trivy reads npm versions from a lockfile, so without one it reports nothing. */
export function npmLockfileMissing(root: string): boolean {
  return fs.existsSync(path.join(root, 'package.json')) && !NPM_LOCKFILES.some((f) => fs.existsSync(path.join(root, f)));
}

export async function runTrivy(binary: string, root: string, outDir: string): Promise<TrivyReport> {
  const report = path.join(outDir, 'trivy.json');
  const args = [
    '--cache-dir', path.join(outDir, 'trivy-cache'),
    'fs',
    '--scanners', 'vuln',
    ...TRIVY_SKIP_DIRS.flatMap((d) => ['--skip-dirs', d]),
    '--format', 'json',
    '--output', report,
    '--severity', TRIVY_SEVERITIES,
    '--quiet',
  ];
  const options = { cwd: root, timeout: TOOL_TIMEOUT_MS, maxBuffer: MAX_TOOL_OUTPUT };
  try {
    await execFileAsync(binary, [...args, root], options);
  } catch (err) {
    const failure = err as { stderr?: string; message?: string };
    if (!MAVEN_RATE_LIMITED_RE.test(`${failure.stderr ?? ''}${failure.message ?? ''}`)) throw err;
    await execFileAsync(binary, [...args, '--offline-scan', root], options);
  }
  return readTrivyReport(await fs.promises.readFile(report, 'utf8'));
}
