import { describe, expect, it } from 'vitest';
import type { SecretFinding, VulnerabilityFinding } from '../src/scan.js';
import { MAX_SENT_FINDINGS, scanPayload } from '../src/scan-payload.js';
import { TOOLS } from '../src/tools.js';

const commit = { head: 'h'.repeat(40), tested: 't'.repeat(40), branch: 'main', pullRequest: null };
const secret = (file: string, line: number): SecretFinding => ({ rule: 'generic-api-key', description: 'Generic API Key', file, line });
const vuln = (id: string, severity: string): VulnerabilityFinding => ({ id, severity, pkg: 'lodash', installed: '4.17.20', fixed: '4.17.21', title: 't', target: 'package-lock.json' });
const flags = { ignoreFile: true, lockfileMissing: false };

describe('scanPayload', () => {
  it('sends both tools with their versions, findings in the summary order, and what Trivy read', () => {
    const payload = scanPayload(
      commit,
      { ok: true, result: [secret('b.ts', 1), secret('a.ts', 9), secret('a.ts', 2)] },
      { ok: true, result: { findings: [vuln('CVE-2', 'LOW'), vuln('CVE-1', 'CRITICAL')], checked: ['package-lock.json'] } },
      { ignoreFile: true, lockfileMissing: true },
    );
    expect(payload).toEqual({
      version: 1,
      commit,
      gitleaks: {
        version: TOOLS.gitleaks.version, status: 'completed', total: 3, ignoreFile: true,
        findings: [secret('a.ts', 2), secret('a.ts', 9), secret('b.ts', 1)],
      },
      trivy: {
        version: TOOLS.trivy.version, status: 'completed', total: 2, lockfileMissing: true, checked: ['package-lock.json'],
        findings: [vuln('CVE-1', 'CRITICAL'), vuln('CVE-2', 'LOW')],
      },
    });
  });

  it('sends a tool that could not run as failed, with its reason', () => {
    const payload = scanPayload(commit, { ok: false, error: 'download failed (HTTP 503)' }, { ok: false, error: 'x509' }, flags);
    expect(payload.gitleaks).toEqual({ version: TOOLS.gitleaks.version, status: 'failed', error: 'download failed (HTTP 503)' });
    expect(payload.trivy).toEqual({ version: TOOLS.trivy.version, status: 'failed', error: 'x509' });
  });

  it(`sends the first ${MAX_SENT_FINDINGS} findings, worst first, and counts them all`, () => {
    const many = Array.from({ length: MAX_SENT_FINDINGS + 5 }, (_, i) => vuln(`CVE-${i}`, i === MAX_SENT_FINDINGS + 4 ? 'CRITICAL' : 'LOW'));
    const payload = scanPayload(commit, { ok: true, result: [] }, { ok: true, result: { findings: many, checked: [] } }, flags);
    expect(payload.trivy.total).toBe(MAX_SENT_FINDINGS + 5);
    expect(payload.trivy.findings).toHaveLength(MAX_SENT_FINDINGS);
    expect(payload.trivy.findings![0].id).toBe(`CVE-${MAX_SENT_FINDINGS + 4}`);
  });

  it('cuts text to the lengths the server accepts', () => {
    const long = { ...vuln('CVE-1', 'HIGH'), title: 'x'.repeat(5000), fixed: 'y'.repeat(5000) };
    const payload = scanPayload(
      commit,
      { ok: true, result: [{ ...secret('f'.repeat(3000), 1), description: 'd'.repeat(3000) }] },
      { ok: true, result: { findings: [long], checked: ['c'.repeat(3000)] } },
      flags,
    );
    expect(payload.gitleaks.findings![0].file).toHaveLength(1024);
    expect(payload.gitleaks.findings![0].description).toHaveLength(1000);
    expect(payload.trivy.findings![0].title).toHaveLength(1000);
    expect(payload.trivy.findings![0].fixed).toHaveLength(1024);
    expect(payload.trivy.checked![0]).toHaveLength(1024);
  });

  it('drops NUL characters, which the server refuses', () => {
    const payload = scanPayload(commit, { ok: true, result: [{ ...secret('a.ts', 1), description: 'Key\u0000 found' }] }, { ok: false, error: 'x\u0000y' }, flags);
    expect(payload.gitleaks.findings![0].description).toBe('Key found');
    expect(payload.trivy.error).toBe('xy');
  });
});
