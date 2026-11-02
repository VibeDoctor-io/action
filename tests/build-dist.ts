import { execFileSync } from 'node:child_process';
import path from 'node:path';

export default function buildDist(): void {
  const root = path.join(import.meta.dirname, '..');
  execFileSync(process.execPath, [path.join(root, 'scripts', 'build.mjs')], { cwd: root, stdio: 'inherit' });
}
