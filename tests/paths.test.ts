import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { isInside, mapReportPaths, repoPathFor, searchBases } from '../src/paths.js';

let root: string;
let ws: string;

function touch(rel: string, base = ws): string {
  const file = path.join(base, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '');
  return file;
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-paths-'));
  ws = path.join(root, 'repo');
  for (const f of ['src/math.js', 'src/app.js', 'packages/web/src/app.js', 'pkg/calc.py', 'coverage/lcov.info']) touch(f);
  touch('outside.js', root);
  fs.mkdirSync(path.join(ws, 'src/dir.js'));
});

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

const lcovAt = (rel: string) => searchBases(path.join(ws, rel), [], ws);

describe('repoPathFor', () => {
  it('turns a Windows-style relative path into a repo path', () => {
    expect(repoPathFor('src\\math.js', lcovAt('coverage/lcov.info'), ws)).toBe('src/math.js');
  });

  it('finds a monorepo package file from its own report folder', () => {
    expect(repoPathFor('src/math.js', lcovAt('packages/web/coverage/lcov.info'), ws)).toBe('src/math.js');
    expect(repoPathFor('src/app.js', lcovAt('packages/web/coverage/lcov.info'), ws)).toBe('packages/web/src/app.js');
  });

  it('uses a Cobertura source inside the workspace first', () => {
    const bases = searchBases(path.join(ws, 'reports/cobertura.xml'), [path.join(ws, 'packages/web')], ws);
    expect(repoPathFor('src/app.js', bases, ws)).toBe('packages/web/src/app.js');
  });

  it('falls back to the report folders when the source is from another machine', () => {
    const bases = searchBases(path.join(ws, 'coverage.xml'), ['C:\\build\\covtest\\py', '/home/other/py'], ws);
    expect(repoPathFor('pkg/calc.py', bases, ws)).toBe('pkg/calc.py');
  });

  it('accepts an absolute path inside the workspace', () => {
    expect(repoPathFor(path.join(ws, 'pkg/calc.py'), [], ws)).toBe('pkg/calc.py');
  });

  it('drops an absolute path outside the workspace', () => {
    expect(repoPathFor(path.join(root, 'outside.js'), lcovAt('coverage/lcov.info'), ws)).toBeNull();
  });

  it('drops a relative path that climbs out of the workspace', () => {
    expect(repoPathFor('../outside.js', [ws], ws)).toBeNull();
    expect(repoPathFor('..\\outside.js', [ws], ws)).toBeNull();
  });

  it('drops a file that does not exist and a folder', () => {
    expect(repoPathFor('src/missing.js', lcovAt('coverage/lcov.info'), ws)).toBeNull();
    expect(repoPathFor('src/dir.js', lcovAt('coverage/lcov.info'), ws)).toBeNull();
  });
});

describe('searchBases', () => {
  it('walks from the report folder up to the workspace, nearest first', () => {
    expect(lcovAt('packages/web/coverage/lcov.info')).toEqual([
      path.join(ws, 'packages/web/coverage'),
      path.join(ws, 'packages/web'),
      path.join(ws, 'packages'),
      ws,
    ]);
  });

  it('uses only the workspace for a report outside it', () => {
    expect(searchBases(path.join(root, 'elsewhere/lcov.info'), [], ws)).toEqual([ws]);
  });
});

describe('mapReportPaths', () => {
  it('keeps only files found in the repository, keyed as the report wrote them', () => {
    expect(mapReportPaths(['src\\math.js', 'src/missing.js', '../outside.js'], lcovAt('coverage/lcov.info'), ws)).toEqual({
      'src\\math.js': 'src/math.js',
    });
  });
});

describe('isInside', () => {
  it('treats the root and its children as inside', () => {
    expect(isInside(ws, ws)).toBe(true);
    expect(isInside(path.join(ws, 'a/b'), ws)).toBe(true);
    expect(isInside(path.join(ws, '..foo'), ws)).toBe(true);
  });

  it('treats parents and siblings as outside', () => {
    expect(isInside(root, ws)).toBe(false);
    expect(isInside(path.join(root, 'repo-other'), ws)).toBe(false);
  });
});
