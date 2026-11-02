import type { SecretFinding, TrivyReport, VulnerabilityFinding } from './scan.js';
import { TOOLS } from './tools.js';

export type ToolOutcome<R> = { ok: true; result: R } | { ok: false; error: string };

export const MAX_SUMMARY_ROWS = 50;
export const MAX_LISTED_FILES = 5;
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

/** Values come from the scanned repo, so nothing in them may close a table cell, open HTML or turn into markdown (`__init__.py` would show a bold "init"). */
export function cell(value: string | number | null): string {
  if (value === null || value === '') return ' ';
  return String(value)
    .replace(/[\r\n]+/g, ' ')
    .replace(/[\\`*_[\]~!|]/g, '\\$&')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const table = (head: string[], rows: Array<Array<string | number | null>>) =>
  [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`)].join('\n');

const more = (total: number) => (total > MAX_SUMMARY_ROWS ? `\n\nShowing ${MAX_SUMMARY_ROWS} of ${total}.` : '');

function listFiles(files: string[]): string {
  const shown = files.slice(0, MAX_LISTED_FILES).map(cell);
  if (files.length > MAX_LISTED_FILES) return `${shown.join(', ')} and ${files.length - MAX_LISTED_FILES} more`;
  return shown.length > 1 ? `${shown.slice(0, -1).join(', ')} and ${shown.at(-1)}` : shown.join('');
}

/** By file and line, since Gitleaks' own order varies between runs. */
export function sortSecrets(findings: SecretFinding[]): SecretFinding[] {
  return [...findings].sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

function secretsSection(outcome: ToolOutcome<SecretFinding[]>): string {
  const tool = `Gitleaks ${TOOLS.gitleaks.version}`;
  if (!outcome.ok) return `### Secrets\n\n${tool} could not run: ${cell(outcome.error)}`;
  const findings = outcome.result;
  if (findings.length === 0) return `### Secrets\n\n${tool} found no secrets.`;
  const rows = sortSecrets(findings)
    .slice(0, MAX_SUMMARY_ROWS)
    .map((f) => [f.rule, f.file, f.line || null]);
  return `### Secrets\n\n${tool} found ${findings.length} ${findings.length === 1 ? 'secret' : 'secrets'}. Their values are hidden.\n\n${table(['Rule', 'File', 'Line'], rows)}${more(findings.length)}`;
}

export function sortVulnerabilities(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const rank = (s: string) => (SEVERITIES.includes(s) ? SEVERITIES.indexOf(s) : SEVERITIES.length);
  return [...findings].sort((a, b) => rank(a.severity) - rank(b.severity) || a.pkg.localeCompare(b.pkg) || a.id.localeCompare(b.id));
}

export const NO_LOCKFILE_NOTE = 'package.json has no lockfile, so Trivy could not check its npm packages. Commit package-lock.json, yarn.lock, pnpm-lock.yaml or bun.lock to have them checked.';

function vulnerabilitiesSection(outcome: ToolOutcome<TrivyReport>, lockfileMissing: boolean): string {
  const tool = `Trivy ${TOOLS.trivy.version}`;
  if (!outcome.ok) return `### Vulnerable dependencies\n\n${tool} could not run: ${cell(outcome.error)}`;
  const note = lockfileMissing ? `\n\n${NO_LOCKFILE_NOTE}` : '';
  const { findings, checked } = outcome.result;
  if (findings.length === 0) {
    const verdict = checked.length === 0 ? 'found no dependency files to check' : `found no vulnerable dependencies in ${listFiles(checked)}`;
    return `### Vulnerable dependencies\n\n${tool} ${verdict}.${note}`;
  }
  const counts = SEVERITIES
    .map((s) => [s, findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s.toLowerCase()}`)
    .join(', ');
  const rows = sortVulnerabilities(findings).slice(0, MAX_SUMMARY_ROWS)
    .map((f) => [f.severity.toLowerCase(), f.pkg, f.installed, f.fixed, f.id, f.target]);
  return `### Vulnerable dependencies\n\n${tool} found ${findings.length}: ${counts}.${note}\n\n${table(['Severity', 'Package', 'Installed', 'Fixed in', 'ID', 'File'], rows)}${more(findings.length)}`;
}

export function scanSummary(
  secrets: ToolOutcome<SecretFinding[]>,
  vulnerabilities: ToolOutcome<TrivyReport>,
  { lockfileMissing = false }: { lockfileMissing?: boolean } = {},
): string {
  return `## VibeDoctor scan\n\n${secretsSection(secrets)}\n\n${vulnerabilitiesSection(vulnerabilities, lockfileMissing)}\n`;
}
