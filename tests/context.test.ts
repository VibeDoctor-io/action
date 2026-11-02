import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { readCommitInfo } from '../src/context.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-context-'));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

function eventFile(name: string, body: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, body);
  return file;
}

describe('readCommitInfo', () => {
  it('uses the PR head commit, PR number and head branch on pull_request', () => {
    const event = eventFile('pr.json', JSON.stringify({ pull_request: { number: 42, head: { sha: 'head123' } } }));
    expect(
      readCommitInfo({ GITHUB_EVENT_PATH: event, GITHUB_SHA: 'merge456', GITHUB_HEAD_REF: 'feature', GITHUB_REF_NAME: '42/merge' }),
    ).toEqual({ head: 'head123', tested: 'merge456', branch: 'feature', pullRequest: 42 });
  });

  it('uses the pushed commit and branch on push', () => {
    const event = eventFile('push.json', JSON.stringify({ ref: 'refs/heads/main', after: 'abc' }));
    expect(readCommitInfo({ GITHUB_EVENT_PATH: event, GITHUB_SHA: 'abc', GITHUB_HEAD_REF: '', GITHUB_REF_NAME: 'main' })).toEqual({
      head: 'abc',
      tested: 'abc',
      branch: 'main',
      pullRequest: null,
    });
  });

  it('treats a missing or broken event file as a push', () => {
    const broken = eventFile('broken.json', '{not json');
    for (const GITHUB_EVENT_PATH of [undefined, broken, path.join(dir, 'none.json')]) {
      expect(readCommitInfo({ GITHUB_EVENT_PATH, GITHUB_SHA: 'abc', GITHUB_REF_NAME: 'main' })).toEqual({
        head: 'abc',
        tested: 'abc',
        branch: 'main',
        pullRequest: null,
      });
    }
  });

  it('ignores a PR number or head commit of the wrong type', () => {
    const event = eventFile('odd.json', JSON.stringify({ pull_request: { number: '7', head: { sha: 9 } } }));
    expect(readCommitInfo({ GITHUB_EVENT_PATH: event, GITHUB_SHA: 'abc', GITHUB_REF_NAME: 'main' })).toMatchObject({
      head: 'abc',
      pullRequest: null,
    });
  });
});
