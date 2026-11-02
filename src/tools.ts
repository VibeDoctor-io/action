import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export type ToolName = 'gitleaks' | 'trivy';
export type Arch = 'x64' | 'arm64';

interface Asset {
  file: string;
  sha256: string;
}

export interface ToolRelease {
  version: string;
  base: string;
  assets: Record<Arch, Asset>;
}

/** The versions our server runs (vibedoctor-engine/Dockerfile); hashes from each release's own checksums file. */
export const TOOLS: Record<ToolName, ToolRelease> = {
  gitleaks: {
    version: '8.30.1',
    base: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/',
    assets: {
      x64: { file: 'gitleaks_8.30.1_linux_x64.tar.gz', sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb' },
      arm64: { file: 'gitleaks_8.30.1_linux_arm64.tar.gz', sha256: 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080' },
    },
  },
  trivy: {
    version: '0.74.0',
    base: 'https://github.com/aquasecurity/trivy/releases/download/v0.74.0/',
    assets: {
      x64: { file: 'trivy_0.74.0_Linux-64bit.tar.gz', sha256: '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a' },
      arm64: { file: 'trivy_0.74.0_Linux-ARM64.tar.gz', sha256: 'b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5' },
    },
  },
};

const DOWNLOAD_TIMEOUT_MS = 120_000;

/** Our pinned downloads are Linux builds. */
export function runnerArch(platform: string = process.platform, arch: string = process.arch): Arch | null {
  if (platform !== 'linux') return null;
  return arch === 'x64' || arch === 'arm64' ? arch : null;
}

export class ChecksumMismatch extends Error {}

export function installTool(name: ToolName, arch: Arch, dir: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  return installRelease(name, TOOLS[name], arch, dir, fetchImpl);
}

/** Downloads the release, refuses it unless its SHA-256 matches, and unpacks only the tool's binary into `dir`. */
export async function installRelease(name: ToolName, release: ToolRelease, arch: Arch, dir: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  const { version, base, assets } = release;
  const asset = assets[arch];
  const response = await fetchImpl(base + asset.file, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`${name} ${version} download failed (HTTP ${response.status})`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (crypto.createHash('sha256').update(bytes).digest('hex') !== asset.sha256) {
    throw new ChecksumMismatch(`${name} ${version} download does not match its published checksum, so it was not run`);
  }
  const archive = path.join(dir, asset.file);
  await fs.promises.writeFile(archive, bytes);
  try {
    await execFileAsync('tar', ['-xzf', archive, '-C', dir, name]);
  } finally {
    fs.rmSync(archive, { force: true });
  }
  return path.join(dir, name);
}
