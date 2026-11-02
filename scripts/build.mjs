import fs from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';

const result = await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/index.js',
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'esm',
  metafile: true,
  banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
});

const packageDirs = new Set();
for (const input of Object.keys(result.metafile.inputs)) {
  const match = input.match(/^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//);
  if (match) packageDirs.add(match[1]);
}

const notices = [...packageDirs].sort().map((dir) => {
  const { name, version, license, author } = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const licenseFile = fs.readdirSync(dir).find((f) => /^licen[cs]e/i.test(f));
  if (licenseFile) return `${name}@${version}\n\n${fs.readFileSync(path.join(dir, licenseFile), 'utf8').trim()}\n`;
  if (!license) throw new Error(`No license in ${dir}`);
  return `${name}@${version}\n\nLicense: ${license}${author ? `, by ${typeof author === 'string' ? author : author.name}` : ''}\n`;
});
fs.writeFileSync('dist/licenses.txt', notices.join('\n---\n\n'));
console.log(`Built dist/index.js with ${packageDirs.size} bundled packages`);
