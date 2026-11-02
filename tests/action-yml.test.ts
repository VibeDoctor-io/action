import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const root = path.join(import.meta.dirname, '..');
const metadata = parse(fs.readFileSync(path.join(root, 'action.yml'), 'utf8'));

function inputsReadBySource(): string[] {
  const src = path.join(root, 'src');
  const names = fs.readdirSync(src)
    .filter((f) => f.endsWith('.ts'))
    .flatMap((f) => [...fs.readFileSync(path.join(src, f), 'utf8').matchAll(/get(?:Boolean|Multiline)?Input\('([^']+)'\)/g)].map((m) => m[1]));
  return [...new Set(names)].sort();
}

describe('action.yml', () => {
  it('declares exactly the inputs the source reads', () => {
    expect(Object.keys(metadata.inputs).sort()).toEqual(inputsReadBySource());
  });

  it('runs the built bundle on Node 24', () => {
    expect(metadata.runs).toEqual({ using: 'node24', main: 'dist/index.js' });
    expect(fs.existsSync(path.join(root, metadata.runs.main))).toBe(true);
  });

  it('has a Marketplace badge in a color GitHub accepts', () => {
    expect(['white', 'black', 'yellow', 'blue', 'green', 'orange', 'red', 'purple', 'gray-dark']).toContain(metadata.branding.color);
    expect(metadata.branding.icon).toMatch(/^[a-z0-9-]+$/);
  });
});
