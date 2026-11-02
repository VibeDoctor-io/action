import type { CommitInfo } from './context.js';
import type { ReportFormat } from './report.js';
import type { SecretFinding, VulnerabilityFinding } from './scan.js';
import packageJson from '../package.json' with { type: 'json' };

export const OIDC_AUDIENCE = 'https://vibedoctor.io';
export const DEFAULT_API_URL = 'https://vibedoctor.io';
export const COVERAGE_ROUTE = '/api/ci/coverage';
export const SCAN_ROUTE = '/api/ci/scan';

export interface UploadReport {
  name: string;
  format: ReportFormat;
  paths: Record<string, string>;
  content: string;
}

export interface CoveragePayload {
  version: 1;
  commit: CommitInfo;
  reports: UploadReport[];
}

interface ScanToolPayload {
  version: string;
  status: 'completed' | 'failed';
  error?: string;
  total?: number;
}

export interface ScanPayload {
  version: 1;
  commit: CommitInfo;
  gitleaks: ScanToolPayload & { ignoreFile?: boolean; findings?: SecretFinding[] };
  trivy: ScanToolPayload & { lockfileMissing?: boolean; checked?: string[]; findings?: VulnerabilityFinding[] };
}

export interface UploadResult {
  sent: boolean;
  message: string;
}

interface Upload {
  route: string;
  sent: string;
  what: string;
  notSent: string;
}

const COVERAGE: Upload = { route: COVERAGE_ROUTE, sent: 'Coverage sent to VibeDoctor.', what: 'the coverage', notSent: 'Coverage was not sent' };
const SCAN: Upload = { route: SCAN_ROUTE, sent: 'Scan results sent to VibeDoctor.', what: 'the scan results', notSent: 'Scan results were not sent' };

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const ATTEMPTS = 2;
const RETRY_DELAY_MS = 2000;
const TIMEOUT_MS = 30000;
const MAX_MESSAGE_LENGTH = 300;

/** A bare host gets the route; an address with a path is used as given. */
function uploadUrl(apiUrl: string, route: string): URL {
  const base = new URL(apiUrl);
  return base.pathname === '/' ? new URL(route, base) : base;
}

export function sendCoverage(
  apiUrl: string, nextToken: () => Promise<string>, payload: CoveragePayload, fetchImpl: typeof fetch = fetch, retryDelayMs = RETRY_DELAY_MS,
): Promise<UploadResult> {
  return send(COVERAGE, apiUrl, nextToken, payload, fetchImpl, retryDelayMs);
}

export function sendScan(
  apiUrl: string, nextToken: () => Promise<string>, payload: ScanPayload, fetchImpl: typeof fetch = fetch, retryDelayMs = RETRY_DELAY_MS,
): Promise<UploadResult> {
  return send(SCAN, apiUrl, nextToken, payload, fetchImpl, retryDelayMs);
}

async function send(
  upload: Upload, apiUrl: string, nextToken: () => Promise<string>, payload: object, fetchImpl: typeof fetch, retryDelayMs: number,
): Promise<UploadResult> {
  const url = uploadUrl(apiUrl, upload.route);
  if (url.protocol !== 'https:' && !LOCAL_HOSTS.has(url.hostname)) {
    return { sent: false, message: `api-url must use https (got ${url.origin}). ${upload.notSent}.` };
  }
  const body = JSON.stringify(payload);
  let failure = '';

  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    if (attempt > 1) await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    try {
      const token = await nextToken();
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'user-agent': `vibedoctor-action/${packageJson.version}`,
        },
        body,
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      const serverMessage = await readMessage(response);
      if (response.ok) return { sent: true, message: serverMessage || upload.sent };
      if (response.status < 500) {
        return {
          sent: false,
          message: `VibeDoctor did not accept ${upload.what} (HTTP ${response.status})${serverMessage ? `: ${serverMessage}` : '.'}`,
        };
      }
      failure = `HTTP ${response.status}`;
    } catch (err) {
      failure = err instanceof Error ? err.message : String(err);
    }
  }
  return { sent: false, message: `Could not reach VibeDoctor (${failure}). ${upload.notSent}; this job is not affected.` };
}

async function readMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { message?: unknown } | null;
    if (typeof body?.message !== 'string') return '';
    // core.info prints this unescaped, so a line break could start a workflow command.
    return body.message.replace(/[\x00-\x1f\x7f]+/g, ' ').trim().slice(0, MAX_MESSAGE_LENGTH);
  } catch {
    return '';
  }
}
