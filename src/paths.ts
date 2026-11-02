import fs from 'node:fs';
import path from 'node:path';

export function searchBases(reportFile: string, sources: string[], workspace: string): string[] {
  const reportDir = path.dirname(path.resolve(workspace, reportFile));
  const bases = sources.map((source) => path.resolve(reportDir, toSlashes(source)));

  for (let dir = reportDir; isInside(dir, workspace); dir = path.dirname(dir)) {
    bases.push(dir);
    if (dir === path.dirname(dir)) break;
  }
  bases.push(workspace);
  return [...new Set(bases)];
}

export function repoPathFor(reportPath: string, bases: string[], workspace: string): string | null {
  const target = toSlashes(reportPath);
  const candidates = path.isAbsolute(target) ? [target] : bases.map((base) => path.resolve(base, target));

  for (const candidate of candidates) {
    if (isInside(candidate, workspace) && isFile(candidate)) {
      return path.relative(workspace, candidate).split(path.sep).join('/');
    }
  }
  return null;
}

export function mapReportPaths(files: string[], bases: string[], workspace: string): Record<string, string> {
  const found = files.map((file) => [file, repoPathFor(file, bases, workspace)] as const);
  return Object.fromEntries(found.filter((entry): entry is readonly [string, string] => entry[1] !== null));
}

export function isInside(target: string, root: string): boolean {
  const rel = path.relative(root, target);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}

function toSlashes(value: string): string {
  return value.replace(/\\/g, '/');
}

export function isFile(file: string): boolean {
  return fs.statSync(file, { throwIfNoEntry: false })?.isFile() ?? false;
}
