import type { CommitInfo } from './context.js';
import type { SecretFinding, TrivyReport, VulnerabilityFinding } from './scan.js';
import { sortSecrets, sortVulnerabilities, type ToolOutcome } from './summary.js';
import { TOOLS, type ToolName } from './tools.js';
import type { ScanPayload } from './upload.js';

/** The server's limit; `total` still counts the rest. */
export const MAX_SENT_FINDINGS = 1000;
const MAX_CHECKED_FILES = 500;

// The server refuses NUL characters.
const cut = (value: string, max: number) => value.replace(/\0/g, '').slice(0, max);

function tool<R>(name: ToolName, outcome: ToolOutcome<R>) {
  return outcome.ok
    ? { version: TOOLS[name].version, status: 'completed' as const }
    : { version: TOOLS[name].version, status: 'failed' as const, error: cut(outcome.error, 1000) };
}

const secret = (f: SecretFinding): SecretFinding => ({
  rule: cut(f.rule, 255), description: cut(f.description, 1000), file: cut(f.file, 1024), line: f.line,
});

const vulnerability = (v: VulnerabilityFinding): VulnerabilityFinding => ({
  id: cut(v.id, 255),
  severity: cut(v.severity, 32),
  pkg: cut(v.pkg, 512),
  installed: cut(v.installed, 255),
  fixed: v.fixed === null ? null : cut(v.fixed, 1024),
  title: cut(v.title, 1000),
  target: cut(v.target, 1024),
});

export function scanPayload(
  commit: CommitInfo,
  secrets: ToolOutcome<SecretFinding[]>,
  vulnerabilities: ToolOutcome<TrivyReport>,
  { ignoreFile, lockfileMissing }: { ignoreFile: boolean; lockfileMissing: boolean },
): ScanPayload {
  return {
    version: 1,
    commit,
    gitleaks: secrets.ok
      ? {
        ...tool('gitleaks', secrets),
        total: secrets.result.length,
        ignoreFile,
        findings: sortSecrets(secrets.result).slice(0, MAX_SENT_FINDINGS).map(secret),
      }
      : tool('gitleaks', secrets),
    trivy: vulnerabilities.ok
      ? {
        ...tool('trivy', vulnerabilities),
        total: vulnerabilities.result.findings.length,
        lockfileMissing,
        checked: vulnerabilities.result.checked.slice(0, MAX_CHECKED_FILES).map((f) => cut(f, 1024)),
        findings: sortVulnerabilities(vulnerabilities.result.findings).slice(0, MAX_SENT_FINDINGS).map(vulnerability),
      }
      : tool('trivy', vulnerabilities),
  };
}
