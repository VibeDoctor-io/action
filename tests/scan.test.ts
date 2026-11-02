import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  failureReason, npmLockfileMissing, readGitleaksReport, readTrivyReport, runGitleaks, runTrivy, trackedTree, TRIVY_SEVERITIES, TRIVY_SKIP_DIRS,
} from '../src/scan.js';

const SECRET = 'AKIAZ7EXAMPLESECRET42';

let dir: string;
let ws: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-'));
  ws = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(ws, { recursive: true, force: true });
});

/** A fake tool: records its arguments, then writes `report` to the path after `flag`. */
function fakeTool(name: string, flag: string, report: string, failFirst = ''): string {
  const bin = path.join(dir, name);
  const reportFile = path.join(dir, `${name}-report.json`);
  fs.writeFileSync(reportFile, report);
  fs.writeFileSync(bin, [
    '#!/bin/sh',
    `echo "$@" >> "${dir}/${name}.args"`,
    failFirst ? `if [ ! -f "${dir}/${name}.failed" ]; then touch "${dir}/${name}.failed"; echo "${failFirst}" >&2; exit 1; fi` : '',
    `out=""; prev=""; for a in "$@"; do if [ "$prev" = "${flag}" ]; then out="$a"; fi; prev="$a"; done`,
    `cp "${reportFile}" "$out"`,
  ].join('\n'), { mode: 0o755 });
  return bin;
}
const args = (name: string) => fs.readFileSync(path.join(dir, `${name}.args`), 'utf8').trim().split('\n');

const GITLEAKS_REPORT = JSON.stringify([{
  RuleID: 'aws-access-token', Description: 'AWS access key', File: 'src/config.ts', StartLine: 12,
  Secret: SECRET, Match: `key = "${SECRET}"`, Line: `const key = "${SECRET}";`, Fingerprint: `src/config.ts:aws-access-token:12`,
}]);

describe('reading the reports', () => {
  it('keeps only rule, description, file and line from Gitleaks: the secret, match and line never come through', () => {
    const findings = readGitleaksReport(GITLEAKS_REPORT);
    expect(findings).toEqual([{ rule: 'aws-access-token', description: 'AWS access key', file: 'src/config.ts', line: 12 }]);
    expect(JSON.stringify(findings)).not.toContain(SECRET);
    expect(readGitleaksReport('[]')).toEqual([]);
    expect(() => readGitleaksReport('{}')).toThrow('not a list');
  });

  it("flattens Trivy's results, with the file each was found in, and lists every dependency file it read", () => {
    const report = JSON.stringify({ Results: [
      { Target: 'package-lock.json', Class: 'lang-pkgs', Vulnerabilities: [{ VulnerabilityID: 'CVE-2024-1', Severity: 'HIGH', PkgName: 'lodash', InstalledVersion: '4.17.20', FixedVersion: '4.17.21', Title: 'Prototype pollution' }] },
      { Target: 'requirements.txt', Class: 'lang-pkgs', Vulnerabilities: null },
      { Target: 'go.sum', Class: 'lang-pkgs', Vulnerabilities: [{ VulnerabilityID: 'GHSA-x', PkgName: 'x/net', InstalledVersion: '0.1.0' }] },
      { Target: 'src/config.js', Class: 'secret' },
    ] });
    expect(readTrivyReport(report)).toEqual({
      findings: [
        { id: 'CVE-2024-1', severity: 'HIGH', pkg: 'lodash', installed: '4.17.20', fixed: '4.17.21', title: 'Prototype pollution', target: 'package-lock.json' },
        { id: 'GHSA-x', severity: 'UNKNOWN', pkg: 'x/net', installed: '0.1.0', fixed: null, title: '', target: 'go.sum' },
      ],
      checked: ['package-lock.json', 'requirements.txt', 'go.sum'],
    });
    expect(readTrivyReport('{}')).toEqual({ findings: [], checked: [] });
  });
});

describe('trackedTree', () => {
  const git = (...a: string[]) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { cwd: ws, stdio: 'pipe' });

  it('holds hard links to the tracked files only, never what the job made after checkout', async () => {
    git('init', '-q');
    fs.mkdirSync(path.join(ws, 'src'));
    fs.writeFileSync(path.join(ws, 'src', 'config.js'), 'tracked');
    fs.writeFileSync(path.join(ws, 'gone.txt'), 'deleted after commit');
    fs.symlinkSync('src/config.js', path.join(ws, 'link.js'));
    git('add', '.');
    git('commit', '-qm', 'init');
    fs.rmSync(path.join(ws, 'gone.txt'));
    for (const made of ['coverage/lcov-report/config.js.html', 'dist/app.js', '.venv/lib/x.py', 'untracked.js']) {
      fs.mkdirSync(path.dirname(path.join(ws, made)), { recursive: true });
      fs.writeFileSync(path.join(ws, made), 'made by the job');
    }

    const tree = await trackedTree(ws, path.join(dir, 'repo'));
    expect(tree).toBe(path.join(dir, 'repo'));
    expect(fs.readdirSync(tree!, { recursive: true }).map(String).sort()).toEqual(['src', path.join('src', 'config.js')]);
    expect(fs.statSync(path.join(tree!, 'src', 'config.js')).ino).toBe(fs.statSync(path.join(ws, 'src', 'config.js')).ino);
  });

  it('is null when the workspace is not a git checkout', async () => {
    expect(await trackedTree(ws, path.join(dir, 'repo'))).toBeNull();
  });
});

describe('npmLockfileMissing', () => {
  it('is true only for a root package.json with none of the lockfiles Trivy reads', () => {
    expect(npmLockfileMissing(ws)).toBe(false);
    fs.writeFileSync(path.join(ws, 'package.json'), '{}');
    expect(npmLockfileMissing(ws)).toBe(true);
    for (const lockfile of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lock']) {
      fs.writeFileSync(path.join(ws, lockfile), '');
      expect(npmLockfileMissing(ws)).toBe(false);
      fs.rmSync(path.join(ws, lockfile));
    }
  });
});

describe('running the tools', () => {
  it('runs Gitleaks on the workspace with --redact and an exit code that never fails the job, honouring .gitleaksignore', async () => {
    fs.writeFileSync(path.join(ws, '.gitleaksignore'), 'src/config.ts:aws-access-token:12\n');
    const findings = await runGitleaks(fakeTool('gitleaks', '--report-path', GITLEAKS_REPORT), ws, dir);
    expect(findings).toHaveLength(1);
    expect(args('gitleaks')).toEqual([
      `dir . --redact --report-format json --report-path ${dir}/gitleaks.json --no-banner --exit-code 0 --gitleaks-ignore-path ${ws}/.gitleaksignore`,
    ]);
  });

  it("runs Trivy's vulnerability scanner with the server's severities and skipped folders, its database in our temp folder", async () => {
    await runTrivy(fakeTool('trivy', '--output', '{"Results":[]}'), ws, dir);
    const skips = TRIVY_SKIP_DIRS.map((d) => `--skip-dirs ${d}`).join(' ');
    expect(args('trivy')).toEqual([
      `--cache-dir ${dir}/trivy-cache fs --scanners vuln ${skips} --format json --output ${dir}/trivy.json --severity ${TRIVY_SEVERITIES} --quiet ${ws}`,
    ]);
    expect(TRIVY_SEVERITIES).toBe('CRITICAL,HIGH,MEDIUM,LOW');
  });

  it('reruns Trivy without Maven lookups when Maven Central rate-limits it, as the server does', async () => {
    await runTrivy(fakeTool('trivy', '--output', '{"Results":[]}', 'Maven repository returned 429'), ws, dir);
    expect(args('trivy')[1]).toContain('--offline-scan');
    const other = fakeTool('trivy', '--output', '{}', 'database download failed');
    fs.rmSync(path.join(dir, 'trivy.failed'), { force: true });
    await expect(runTrivy(other, ws, dir)).rejects.toThrow('database download failed');
  });

  it('says why a tool failed in its own words, not by repeating the command line', async () => {
    const bin = path.join(dir, 'broken');
    fs.writeFileSync(bin, '#!/bin/sh\necho "FATAL run error: DB error:" >&2\necho "  * tls: failed to verify certificate" >&2\nexit 1\n', { mode: 0o755 });
    expect(failureReason(await runTrivy(bin, ws, dir).catch((e: unknown) => e))).toBe('* tls: failed to verify certificate');
    expect(failureReason(new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND github.com') }))).toBe('fetch failed (getaddrinfo ENOTFOUND github.com)');
    expect(failureReason(Object.assign(new Error('Command failed: trivy fs'), { killed: true, stderr: '' }))).toBe('it did not finish within 10 minutes');
    expect(failureReason('x'.repeat(400))).toHaveLength(300);
  });
});
