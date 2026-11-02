import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ENTRIES = ['.gitattributes', '.github', '.gitignore', 'LICENSE', 'README.md', 'action.yml', 'dist', 'package-lock.json', 'package.json', 'scripts', 'src', 'tests', 'tsconfig.json', 'vitest.config.ts'];

if (!process.argv[2]) {
  console.error('Usage: node scripts/export.mjs <folder of the VibeDoctor-io/action clone>');
  process.exit(1);
}
const root = path.join(import.meta.dirname, '..');
const target = path.resolve(process.argv[2]);
const within = (parent, child) => {
  const rel = path.relative(parent, child);
  return rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
};
if (within(root, target) || within(target, root)) {
  console.error(`Nothing exported: ${target} overlaps the action folder ${root}`);
  process.exit(1);
}
fs.mkdirSync(target, { recursive: true });
const unknown = fs.readdirSync(target).filter((name) => name !== '.git' && !ENTRIES.includes(name));
if (unknown.length > 0) {
  console.error(`Nothing exported: ${target} also holds ${unknown.join(', ')}`);
  process.exit(1);
}

execFileSync(process.execPath, [path.join(root, 'scripts', 'build.mjs')], { cwd: root, stdio: 'inherit' });
for (const name of ENTRIES) {
  fs.rmSync(path.join(target, name), { recursive: true, force: true });
  fs.cpSync(path.join(root, name), path.join(target, name), { recursive: true });
}
console.log(`Exported ${ENTRIES.length} entries to ${target}`);
