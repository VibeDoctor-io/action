import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const ACTION = path.join(import.meta.dirname, '..', 'dist', 'index.js');
const FIXTURES = path.join(import.meta.dirname, 'fixtures');
const OIDC_TOKEN = 'fake-oidc-token-123';

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

let server: http.Server;
let base: string;
let seen: Seen[];
let apiReply: { status: number; body: unknown };
let apiReplies: Array<{ status: number; body: unknown }>;
let root: string;
let ws: string;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
      const reply = req.url!.startsWith('/token') ? { status: 200, body: { value: OIDC_TOKEN } } : (apiReplies.shift() ?? apiReply);
      res.writeHead(reply.status, { 'content-type': 'application/json' }).end(JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  root = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-action-'));
  ws = path.join(root, 'repo');
  const place = (fixture: string, rel: string) => {
    fs.mkdirSync(path.dirname(path.join(ws, rel)), { recursive: true });
    fs.copyFileSync(path.join(FIXTURES, fixture), path.join(ws, rel));
  };
  place('vitest-lcov.info', 'packages/web/coverage/lcov.info');
  place('coveragepy.xml', 'coverage.xml');
  place('jest-clover.xml', 'jest/coverage/clover.xml');
  for (const f of ['packages/web/src/math.js', 'pkg/__init__.py', 'pkg/calc.py', 'test_calc.py']) {
    fs.mkdirSync(path.dirname(path.join(ws, f)), { recursive: true });
    fs.writeFileSync(path.join(ws, f), '');
  }
  fs.mkdirSync(path.join(ws, 'docker'));
  fs.writeFileSync(path.join(ws, 'docker/lcov.info'), 'SF:/app/src/a.js\nend_of_record\nSF:/app/src/b.js\nend_of_record\n');
  fs.writeFileSync(path.join(ws, 'empty.xml'), '<?xml version="1.0" ?>\n<coverage version="7.6.1"><sources/><packages/></coverage>\n');
  fs.writeFileSync(path.join(root, 'pr-event.json'), JSON.stringify({ pull_request: { number: 7, head: { sha: 'headsha' } } }));
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  seen = [];
  apiReply = { status: 200, body: { message: 'Coverage saved for 1 project.' } };
  apiReplies = [];
});

function runAction(inputs: Record<string, string>, extraEnv: Record<string, string | undefined> = {}) {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    GITHUB_WORKSPACE: ws,
    GITHUB_EVENT_PATH: path.join(root, 'pr-event.json'),
    GITHUB_SHA: 'mergesha',
    GITHUB_HEAD_REF: 'feature',
    GITHUB_REF_NAME: '7/merge',
    ACTIONS_ID_TOKEN_REQUEST_URL: `${base}/token?api-version=2.0`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token',
    'INPUT_API-URL': base,
  };
  for (const [name, value] of Object.entries(inputs)) env[`INPUT_${name.toUpperCase()}`] = value;
  for (const [name, value] of Object.entries(extraEnv)) {
    if (value === undefined) delete env[name];
    else env[name] = value;
  }

  return new Promise<{ code: number | null; stdout: string }>((resolve) => {
    const child = spawn(process.execPath, [ACTION], { cwd: root, env });
    let stdout = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stdout += chunk));
    child.on('close', (code) => resolve({ code, stdout }));
  });
}

const apiCalls = () => seen.filter((s) => s.url.startsWith('/api/'));

describe('the built action', () => {
  it('sends both reports with fixed paths, commit info and the OIDC token', async () => {
    const { code, stdout } = await runAction({ 'coverage-file': 'packages/*/coverage/lcov.info\ncoverage.xml' });
    expect(code).toBe(0);

    const tokenCall = seen.find((s) => s.url.startsWith('/token'))!;
    expect(tokenCall.headers.authorization).toBe('Bearer request-token');
    expect(new URL(tokenCall.url, base).searchParams.get('audience')).toBe('https://vibedoctor.io');

    const [upload] = apiCalls();
    expect(upload.method).toBe('POST');
    expect(upload.url).toBe('/api/ci/coverage');
    expect(upload.headers.authorization).toBe(`Bearer ${OIDC_TOKEN}`);
    expect(upload.headers['user-agent']).toBe('vibedoctor-action/1.0.0');

    const body = JSON.parse(upload.body);
    expect(Object.keys(body).sort()).toEqual(['commit', 'reports', 'version']);
    for (const report of body.reports) expect(Object.keys(report).sort()).toEqual(['content', 'format', 'name', 'paths']);
    expect(body.version).toBe(1);
    expect(body.commit).toEqual({ head: 'headsha', tested: 'mergesha', branch: 'feature', pullRequest: 7 });

    const byName = Object.fromEntries(body.reports.map((r: { name: string }) => [r.name, r]));
    expect(Object.keys(byName).sort()).toEqual(['coverage.xml', 'packages/web/coverage/lcov.info']);
    expect(byName['packages/web/coverage/lcov.info'].format).toBe('lcov');
    expect(byName['packages/web/coverage/lcov.info'].paths).toEqual({ 'src\\math.js': 'packages/web/src/math.js' });
    expect(byName['coverage.xml'].format).toBe('cobertura');
    expect(byName['coverage.xml'].paths).toEqual({
      'test_calc.py': 'test_calc.py',
      'pkg/__init__.py': 'pkg/__init__.py',
      'pkg/calc.py': 'pkg/calc.py',
    });

    expect(zlib.gunzipSync(Buffer.from(byName['coverage.xml'].content, 'base64'))).toEqual(
      fs.readFileSync(path.join(FIXTURES, 'coveragepy.xml')),
    );
    expect(zlib.gunzipSync(Buffer.from(byName['packages/web/coverage/lcov.info'].content, 'base64'))).toEqual(
      fs.readFileSync(path.join(FIXTURES, 'vitest-lcov.info')),
    );

    expect(stdout).toContain('packages/web/coverage/lcov.info: LCOV, 1 of 2 files found in the repository.');
    expect(stdout).toContain('coverage.xml: Cobertura, 3 of 3 files found in the repository.');
    expect(stdout).toContain('Coverage saved for 1 project.');
    expect(stdout).not.toContain('::warning::');
  });

  it('masks the OIDC token and never prints it otherwise', async () => {
    const { stdout } = await runAction({ 'coverage-file': 'coverage.xml' });
    const lines = stdout.split('\n').filter((line) => line.includes(OIDC_TOKEN));
    expect(lines).toEqual([`::add-mask::${OIDC_TOKEN}`]);
  });

  it('warns and passes when VibeDoctor refuses the upload', async () => {
    apiReply = { status: 403, body: { message: 'Coverage needs a Watch, Guard or Shield plan.' } };
    const { code, stdout } = await runAction({ 'coverage-file': 'coverage.xml' });
    expect(code).toBe(0);
    expect(stdout).toContain(
      '::warning::VibeDoctor did not accept the coverage (HTTP 403): Coverage needs a Watch, Guard or Shield plan.',
    );
  });

  it('retries a server error with a new token', async () => {
    apiReplies = [{ status: 503, body: {} }];
    const { code, stdout } = await runAction({ 'coverage-file': 'coverage.xml' });
    expect(code).toBe(0);
    expect(seen.filter((s) => s.url.startsWith('/token'))).toHaveLength(2);
    expect(apiCalls()).toHaveLength(2);
    expect(stdout).toContain('Coverage saved for 1 project.');
  });

  it('warns and passes when VibeDoctor is down', async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const deadUrl = `http://127.0.0.1:${(closed.address() as AddressInfo).port}`;
    await new Promise((resolve) => closed.close(resolve));

    const { code, stdout } = await runAction({ 'coverage-file': 'coverage.xml', 'api-url': deadUrl });
    expect(code).toBe(0);
    expect(stdout).toMatch(/::warning::Could not reach VibeDoctor \(.+\)\. Coverage was not sent; this job is not affected\./);
  });

  it('warns and sends nothing without id-token permission', async () => {
    const { code, stdout } = await runAction(
      { 'coverage-file': 'coverage.xml' },
      { ACTIONS_ID_TOKEN_REQUEST_URL: undefined, ACTIONS_ID_TOKEN_REQUEST_TOKEN: undefined },
    );
    expect(code).toBe(0);
    expect(stdout).toContain('::warning::Could not get a GitHub OIDC token');
    expect(stdout).toContain('Check that the job has "id-token: write" in its permissions. Coverage was not sent.');
    expect(apiCalls()).toEqual([]);
  });

  it('warns when coverage-file is not set', async () => {
    const { code, stdout } = await runAction({});
    expect(code).toBe(0);
    expect(stdout).toContain('::warning::Set coverage-file to the path of your LCOV or Cobertura XML report.');
    expect(seen).toEqual([]);
  });

  it('still sends coverage when scan has a value that is not true or false, and says so', async () => {
    const { code, stdout } = await runAction({ 'coverage-file': 'coverage.xml', scan: 'maybe' });
    expect(code).toBe(0);
    expect(stdout).toContain('::warning::scan must be true or false. The scan was skipped.');
    expect(apiCalls()).toHaveLength(1);
  });

  it('warns about coverage-file only when scan is off too', async () => {
    const { stdout } = await runAction({ scan: 'false' });
    expect(stdout).toContain('::warning::Set coverage-file to the path of your LCOV or Cobertura XML report.');
  });

  it('warns when nothing matches', async () => {
    const { code, stdout } = await runAction({ 'coverage-file': 'missing/lcov.info, also-missing.xml' });
    expect(code).toBe(0);
    expect(stdout).toContain(
      '::warning::No coverage report matched missing/lcov.info, also-missing.xml. Check that the tests ran with coverage on.',
    );
    expect(seen).toEqual([]);
  });

  it('skips a Clover report and sends nothing when no report is left', async () => {
    const { code, stdout } = await runAction({ 'coverage-file': 'jest/coverage/clover.xml' });
    expect(code).toBe(0);
    expect(stdout).toContain(
      '::warning::jest/coverage/clover.xml: Clover XML is not supported, send LCOV or Cobertura XML. Skipped.',
    );
    expect(seen).toEqual([]);
  });

  it('names an example path when none of a report files are in the repository', async () => {
    const { code, stdout } = await runAction({ 'coverage-file': 'docker/lcov.info' });
    expect(code).toBe(0);
    expect(stdout).toContain(
      '::warning::docker/lcov.info: none of its 2 files are in this repository (for example /app/src/a.js). Skipped.',
    );
    expect(seen).toEqual([]);
  });

  it('skips a report that lists no files', async () => {
    const { stdout } = await runAction({ 'coverage-file': 'empty.xml' });
    expect(stdout).toContain('::warning::empty.xml: the report lists no files. Skipped.');
    expect(seen).toEqual([]);
  });

  it('uses the pushed commit when the event is a push', async () => {
    fs.writeFileSync(path.join(root, 'push-event.json'), JSON.stringify({ ref: 'refs/heads/main' }));
    await runAction(
      { 'coverage-file': 'coverage.xml' },
      { GITHUB_EVENT_PATH: path.join(root, 'push-event.json'), GITHUB_SHA: 'pushsha', GITHUB_HEAD_REF: '', GITHUB_REF_NAME: 'main' },
    );
    expect(JSON.parse(apiCalls()[0].body).commit).toEqual({ head: 'pushsha', tested: 'pushsha', branch: 'main', pullRequest: null });
  });
});
