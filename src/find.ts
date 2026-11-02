import fs from 'node:fs';
import path from 'node:path';
import { isFile } from './paths.js';

export async function findReports(patterns: string[], workspace: string): Promise<string[]> {
  const skipped = new Set(await globFiles(patterns.filter(isNegated).map((p) => p.slice(1)), workspace));
  const found = await globFiles(patterns.filter((p) => !isNegated(p)), workspace);
  return found.filter((file) => !skipped.has(file));
}

async function globFiles(patterns: string[], cwd: string): Promise<string[]> {
  if (patterns.length === 0) return [];
  const files = new Set<string>();
  for await (const match of fs.promises.glob(patterns, { cwd, exclude: inNodeModules })) {
    const file = path.resolve(cwd, match);
    if (isFile(file)) files.add(file);
  }
  return [...files];
}

function inNodeModules(entry: string): boolean {
  return entry.split(/[\\/]/).includes('node_modules');
}

function isNegated(pattern: string): boolean {
  return pattern.startsWith('!');
}
