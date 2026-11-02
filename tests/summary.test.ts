import { describe, expect, it } from 'vitest';
import type { SecretFinding, TrivyReport, VulnerabilityFinding } from '../src/scan.js';
import { cell, MAX_LISTED_FILES, MAX_SUMMARY_ROWS, NO_LOCKFILE_NOTE, scanSummary, sortVulnerabilities, type ToolOutcome } from '../src/summary.js';

const secret = (n: number): SecretFinding => ({ rule: 'generic-api-key', description: 'Generic API Key', file: `src/f${n}.ts`, line: n });
const vuln = (id: string, severity: string, pkg = 'lodash'): VulnerabilityFinding => ({ id, severity, pkg, installed: '1.0.0', fixed: '1.0.1', title: 't', target: 'package-lock.json' });
const secrets = (findings: SecretFinding[]): ToolOutcome<SecretFinding[]> => ({ ok: true, result: findings });
const trivy = (findings: VulnerabilityFinding[], checked = ['package-lock.json']): ToolOutcome<TrivyReport> => ({ ok: true, result: { findings, checked } });

describe('scanSummary', () => {
  it('lists secrets by rule, file and line, and dependencies with counts per severity, worst first', () => {
    const md = scanSummary(
      secrets([secret(12)]),
      trivy([vuln('CVE-3', 'LOW', 'a'), vuln('CVE-1', 'CRITICAL', 'b'), vuln('CVE-2', 'HIGH', 'c'), vuln('CVE-4', 'HIGH', 'a')]),
    );
    expect(md).toContain('## VibeDoctor scan');
    expect(md).toContain('Gitleaks 8.30.1 found 1 secret. Their values are hidden.');
    expect(md).toContain('| generic-api-key | src/f12.ts | 12 |');
    expect(md).toContain('Trivy 0.74.0 found 4: 1 critical, 2 high, 1 low.');
    const rows = md.split('\n').filter((l) => l.startsWith('| ') && l.includes('CVE-'));
    expect(rows.map((r) => r.split(' | ')[4])).toEqual(['CVE-1', 'CVE-4', 'CVE-2', 'CVE-3']);
  });

  it('lists secrets by file and line, whatever order Gitleaks wrote them in', () => {
    const md = scanSummary(secrets([secret(9), { ...secret(2), file: 'a.ts' }, { ...secret(1), file: 'a.ts', line: 30 }]), trivy([]));
    expect(md.split('\n').filter((l) => l.startsWith('| generic-api-key'))).toEqual([
      '| generic-api-key | a.ts | 2 |',
      '| generic-api-key | a.ts | 30 |',
      '| generic-api-key | src/f9.ts | 9 |',
    ]);
  });

  it('says when nothing was found, and when a tool could not run', () => {
    expect(scanSummary(secrets([]), trivy([]))).toContain('Gitleaks 8.30.1 found no secrets.');
    const md = scanSummary({ ok: false, error: 'download failed (HTTP 503)' }, trivy([]));
    expect(md).toContain('Gitleaks 8.30.1 could not run: download failed (HTTP 503)');
  });

  it('names the dependency files Trivy read when it found nothing, so a clean result is never a guess', () => {
    expect(scanSummary(secrets([]), trivy([]))).toContain('Trivy 0.74.0 found no vulnerable dependencies in package-lock.json.');
    expect(scanSummary(secrets([]), trivy([], ['go.sum', 'web/package-lock.json']))).toContain('found no vulnerable dependencies in go.sum and web/package-lock.json.');
    const many = Array.from({ length: MAX_LISTED_FILES + 2 }, (_, i) => `m${i}/go.sum`);
    expect(scanSummary(secrets([]), trivy([], many))).toContain('in m0/go.sum, m1/go.sum, m2/go.sum, m3/go.sum, m4/go.sum and 2 more.');
    expect(scanSummary(secrets([]), trivy([], []))).toContain('Trivy 0.74.0 found no dependency files to check.');
  });

  it(`shows the first ${MAX_SUMMARY_ROWS} rows and says how many there were`, () => {
    const md = scanSummary(secrets(Array.from({ length: 60 }, (_, i) => secret(i + 1))), trivy([]));
    expect(md.split('\n').filter((l) => l.startsWith('| generic-api-key')).length).toBe(MAX_SUMMARY_ROWS);
    expect(md).toContain(`Showing ${MAX_SUMMARY_ROWS} of 60.`);
  });

  it('keeps values from the repo from breaking the table, adding HTML or turning into markdown', () => {
    expect(cell('a|b')).toBe('a\\|b');
    expect(cell('<img src=x onerror=alert(1)>')).toBe('&lt;img src=x onerror=alert(1)&gt;');
    expect(cell('line\nbreak')).toBe('line break');
    expect(cell(null)).toBe(' ');
    expect(cell('pkg/__init__.py')).toBe('pkg/\\_\\_init\\_\\_.py');
    expect(cell('![x](https://e.test/p.png) *a* `b` ~c~ \\')).toBe('\\!\\[x\\](https://e.test/p.png) \\*a\\* \\`b\\` \\~c\\~ \\\\');
    const md = scanSummary(secrets([{ ...secret(1), file: 'evil|<b>x</b>.ts' }]), trivy([]));
    expect(md).toContain('| generic-api-key | evil\\|&lt;b&gt;x&lt;/b&gt;.ts | 1 |');
  });

  it('warns that npm packages were not checked when package.json has no lockfile, found or not', () => {
    expect(scanSummary(secrets([]), trivy([], []), { lockfileMissing: true })).toContain(NO_LOCKFILE_NOTE);
    expect(scanSummary(secrets([]), trivy([vuln('CVE-1', 'HIGH')]), { lockfileMissing: true })).toContain(NO_LOCKFILE_NOTE);
    expect(scanSummary(secrets([]), trivy([]))).not.toContain(NO_LOCKFILE_NOTE);
    expect(scanSummary(secrets([]), { ok: false, error: 'x' }, { lockfileMissing: true })).not.toContain(NO_LOCKFILE_NOTE);
  });

  it('puts an unknown severity last', () => {
    expect(sortVulnerabilities([vuln('X', 'WEIRD'), vuln('Y', 'MEDIUM')]).map((v) => v.id)).toEqual(['Y', 'X']);
  });
});
