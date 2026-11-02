import fs from 'node:fs';

export interface CommitInfo {
  head: string;
  tested: string;
  branch: string;
  pullRequest: number | null;
}

export function readCommitInfo(env: NodeJS.ProcessEnv): CommitInfo {
  const pr = readEvent(env.GITHUB_EVENT_PATH)?.pull_request;
  const tested = env.GITHUB_SHA ?? '';
  return {
    head: typeof pr?.head?.sha === 'string' ? pr.head.sha : tested,
    tested,
    branch: env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || '',
    pullRequest: Number.isInteger(pr?.number) ? pr.number : null,
  };
}

function readEvent(eventPath: string | undefined): any {
  if (!eventPath) return null;
  try {
    return JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  } catch {
    return null;
  }
}
