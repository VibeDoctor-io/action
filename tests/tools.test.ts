import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ChecksumMismatch, installRelease, runnerArch, TOOLS, type ToolRelease } from '../src/tools.js';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tools-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** A release tarball holding a `gitleaks` script and a file that must not be unpacked. */
function tarball(): Buffer {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'src-'));
  fs.writeFileSync(path.join(src, 'gitleaks'), '#!/bin/sh\necho ok\n', { mode: 0o755 });
  fs.writeFileSync(path.join(src, 'README.md'), 'not wanted');
  const out = path.join(src, 'release.tar.gz');
  execFileSync('tar', ['-czf', out, '-C', src, 'gitleaks', 'README.md']);
  return fs.readFileSync(out);
}

const serve = (bytes: Buffer, status = 200) => vi.fn(async () => new Response(new Uint8Array(bytes), { status })) as unknown as typeof fetch;
const release = (sha256: string): ToolRelease => ({
  version: '9.9.9',
  base: 'https://example.test/releases/',
  assets: { x64: { file: 'g_linux_x64.tar.gz', sha256 }, arm64: { file: 'g_linux_arm64.tar.gz', sha256 } },
});

describe('runnerArch', () => {
  it('scans on Linux x64 and arm64 only', () => {
    expect([runnerArch('linux', 'x64'), runnerArch('linux', 'arm64'), runnerArch('darwin', 'arm64'), runnerArch('win32', 'x64'), runnerArch('linux', 'ia32')])
      .toEqual(['x64', 'arm64', null, null, null]);
  });
});

describe('installRelease', () => {
  it('unpacks only the binary from a download whose SHA-256 matches', async () => {
    const bytes = tarball();
    const fetchImpl = serve(bytes);
    const binary = await installRelease('gitleaks', release(crypto.createHash('sha256').update(bytes).digest('hex')), 'x64', dir, fetchImpl);
    expect(binary).toBe(path.join(dir, 'gitleaks'));
    expect(execFileSync(binary).toString()).toBe('ok\n');
    expect(fs.readdirSync(dir)).toEqual(['gitleaks']);
    expect(vi.mocked(fetchImpl).mock.calls[0][0]).toBe('https://example.test/releases/g_linux_x64.tar.gz');
  });

  it('refuses a download that does not match its checksum, and writes nothing', async () => {
    const err = await installRelease('gitleaks', release('0'.repeat(64)), 'arm64', dir, serve(tarball())).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ChecksumMismatch);
    expect(String(err)).toContain('does not match its published checksum');
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it('says which tool failed to download', async () => {
    await expect(installRelease('gitleaks', release('0'.repeat(64)), 'x64', dir, serve(Buffer.from('gone'), 404))).rejects.toThrow('gitleaks 9.9.9 download failed (HTTP 404)');
  });
});

describe('pinned releases', () => {
  it("pins the server's versions with a full SHA-256 for each Linux build", () => {
    expect([TOOLS.gitleaks.version, TOOLS.trivy.version]).toEqual(['8.30.1', '0.74.0']);
    for (const { version, base, assets } of Object.values(TOOLS)) {
      expect(base).toMatch(new RegExp(`^https://github\\.com/[^/]+/[^/]+/releases/download/v${version.replace(/\./g, '\\.')}/$`));
      for (const asset of Object.values(assets)) {
        expect(asset.file).toContain(version);
        expect(asset.sha256).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });
});
