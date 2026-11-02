import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { findReports } from '../src/find.js';

let ws: string;
const at = (...rels: string[]) => rels.map((rel) => path.join(ws, rel)).sort();
const find = async (...patterns: string[]) => (await findReports(patterns, ws)).sort();

beforeAll(() => {
  ws = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-find-'));
  for (const rel of [
    'coverage/lcov.info',
    'packages/a/coverage/lcov.info',
    'packages/b/coverage/lcov.info',
    'node_modules/pkg/coverage/lcov.info',
    'packages/a/node_modules/x/coverage/lcov.info',
  ]) {
    fs.mkdirSync(path.dirname(path.join(ws, rel)), { recursive: true });
    fs.writeFileSync(path.join(ws, rel), 'SF:a.js\n');
  }
  fs.mkdirSync(path.join(ws, 'coverage/folder.info'));
});

afterAll(() => fs.rmSync(ws, { recursive: true, force: true }));

describe('findReports', () => {
  it('matches a plain path', async () => {
    expect(await find('coverage/lcov.info')).toEqual(at('coverage/lcov.info'));
  });

  it('matches globs and never looks inside node_modules', async () => {
    expect(await find('**/coverage/lcov.info')).toEqual(
      at('coverage/lcov.info', 'packages/a/coverage/lcov.info', 'packages/b/coverage/lcov.info'),
    );
  });

  it('leaves out files matched by a pattern that starts with !', async () => {
    expect(await find('packages/*/coverage/lcov.info', '!packages/b/**')).toEqual(at('packages/a/coverage/lcov.info'));
  });

  it('returns files only, not folders', async () => {
    expect(await find('coverage/*.info')).toEqual(at('coverage/lcov.info'));
  });

  it('lists a file once when two patterns match it', async () => {
    expect(await find('coverage/lcov.info', 'coverage/*.info')).toEqual(at('coverage/lcov.info'));
  });

  it('accepts an absolute path', async () => {
    expect(await find(path.join(ws, 'packages/b/coverage/lcov.info'))).toEqual(at('packages/b/coverage/lcov.info'));
  });

  it('returns nothing when nothing matches', async () => {
    expect(await find('missing/lcov.info')).toEqual([]);
  });
});
