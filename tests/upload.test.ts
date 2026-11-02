import { describe, expect, it, vi } from 'vitest';
import { COVERAGE_ROUTE, SCAN_ROUTE, sendCoverage, sendScan, type CoveragePayload, type ScanPayload } from '../src/upload.js';

const payload: CoveragePayload = {
  version: 1,
  commit: { head: 'h', tested: 't', branch: 'main', pullRequest: null },
  reports: [{ name: 'coverage/lcov.info', format: 'lcov', paths: { 'src\\a.js': 'src/a.js' }, content: 'H4sI' }],
};

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function fakeFetch(...responses: Array<Response | Error>) {
  return vi.fn(async () => {
    const next = responses.shift();
    if (next instanceof Error) throw next;
    return next!;
  });
}

describe('sendCoverage', () => {
  it('posts the payload with the OIDC token to the coverage route', async () => {
    const fetchImpl = fakeFetch(json(200, { message: 'Coverage saved for 1 project.' }));
    const result = await sendCoverage('https://vibedoctor.io', async () => 'oidc-token', payload, fetchImpl as typeof fetch, 0);

    expect(result).toEqual({ sent: true, message: 'Coverage saved for 1 project.' });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe(`https://vibedoctor.io${COVERAGE_ROUTE}`);
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer oidc-token');
    expect(JSON.parse(init.body as string)).toEqual(payload);
    expect(init.redirect).toBe('error');
  });

  it('prints a server message on one line, cut to 300 characters', async () => {
    const injected = await sendCoverage('https://x.test', async () => 't', payload, fakeFetch(json(200, { message: 'ok\n::error::x\r\n\tdone' })) as typeof fetch, 0);
    expect(injected.message).toBe('ok ::error::x done');

    const long = await sendCoverage('https://x.test', async () => 't', payload, fakeFetch(json(403, { message: 'y'.repeat(1000) })) as typeof fetch, 0);
    expect(long.message).toBe(`VibeDoctor did not accept the coverage (HTTP 403): ${'y'.repeat(300)}`);
  });

  it('ignores a message that is not text', async () => {
    const result = await sendCoverage('https://x.test', async () => 't', payload, fakeFetch(json(200, { message: { a: 1 } })) as typeof fetch, 0);
    expect(result.message).toBe('Coverage sent to VibeDoctor.');
  });

  it('uses a default message when the server sends none', async () => {
    const result = await sendCoverage('https://x.test', async () => 't', payload, fakeFetch(new Response(null, { status: 204 })) as typeof fetch, 0);
    expect(result).toEqual({ sent: true, message: 'Coverage sent to VibeDoctor.' });
  });

  it('reports a refusal with the server message and does not retry', async () => {
    const fetchImpl = fakeFetch(json(403, { message: 'Coverage needs a Watch, Guard or Shield plan.' }));
    const result = await sendCoverage('https://x.test', async () => 't', payload, fetchImpl as typeof fetch, 0);
    expect(result).toEqual({
      sent: false,
      message: 'VibeDoctor did not accept the coverage (HTTP 403): Coverage needs a Watch, Guard or Shield plan.',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reports a refusal without a message', async () => {
    const result = await sendCoverage('https://x.test', async () => 't', payload, fakeFetch(new Response('nope', { status: 413 })) as typeof fetch, 0);
    expect(result.message).toBe('VibeDoctor did not accept the coverage (HTTP 413).');
  });

  it('retries once on a server error, then reports it as down', async () => {
    const fetchImpl = fakeFetch(json(503, {}), json(502, {}));
    const result = await sendCoverage('https://x.test', async () => 't', payload, fetchImpl as typeof fetch, 0);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(result).toEqual({
      sent: false,
      message: 'Could not reach VibeDoctor (HTTP 502). Coverage was not sent; this job is not affected.',
    });
  });

  it('succeeds when the retry after a network error works', async () => {
    const fetchImpl = fakeFetch(new TypeError('fetch failed'), json(200, { message: 'ok' }));
    const result = await sendCoverage('https://x.test', async () => 't', payload, fetchImpl as typeof fetch, 0);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(result).toEqual({ sent: true, message: 'ok' });
  });

  it('refuses to send the token over plain http to a remote host', async () => {
    const fetchImpl = fakeFetch(json(200, {}));
    const result = await sendCoverage('http://vibedoctor.io', async () => 't', payload, fetchImpl as typeof fetch, 0);
    expect(result).toEqual({ sent: false, message: 'api-url must use https (got http://vibedoctor.io). Coverage was not sent.' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each(['http://localhost:3001', 'http://127.0.0.1:3001', 'http://[::1]:3001'])('allows plain http to %s', async (apiUrl) => {
    const result = await sendCoverage(apiUrl, async () => 't', payload, fakeFetch(json(200, {})) as typeof fetch, 0);
    expect(result.sent).toBe(true);
  });

  it('asks for a new token on each try', async () => {
    const tokens = ['first', 'second'];
    const fetchImpl = fakeFetch(json(503, {}), json(200, { message: 'ok' }));
    await sendCoverage('https://x.test', async () => tokens.shift()!, payload, fetchImpl as typeof fetch, 0);
    const sent = fetchImpl.mock.calls.map((call) => ((call as unknown as [URL, RequestInit])[1].headers as Record<string, string>).authorization);
    expect(sent).toEqual(['Bearer first', 'Bearer second']);
  });

  it('posts to an address with a path as given, and adds the route to a bare host', async () => {
    const relay = fakeFetch(json(200, {}));
    await sendCoverage('https://relay.example.test/channel', async () => 't', payload, relay as typeof fetch, 0);
    expect(String((relay.mock.calls[0] as unknown as [URL])[0])).toBe('https://relay.example.test/channel');

    const bare = fakeFetch(json(200, {}));
    await sendCoverage('https://vibedoctor.io/', async () => 't', payload, bare as typeof fetch, 0);
    expect(String((bare.mock.calls[0] as unknown as [URL])[0])).toBe(`https://vibedoctor.io${COVERAGE_ROUTE}`);
  });

  it('reports two network errors as down', async () => {
    const fetchImpl = fakeFetch(new TypeError('fetch failed'), new TypeError('fetch failed'));
    const result = await sendCoverage('https://x.test', async () => 't', payload, fetchImpl as typeof fetch, 0);
    expect(result.message).toBe('Could not reach VibeDoctor (fetch failed). Coverage was not sent; this job is not affected.');
  });
});

describe('sendScan', () => {
  const scan: ScanPayload = {
    version: 1,
    commit: payload.commit,
    gitleaks: { version: '8.30.1', status: 'completed', total: 0, ignoreFile: false, findings: [] },
    trivy: { version: '0.74.0', status: 'failed', error: 'x509' },
  };

  it('posts the scan results with the OIDC token to the scan route', async () => {
    const fetchImpl = fakeFetch(json(200, { message: 'Scan results saved for main.' }));
    const result = await sendScan('https://vibedoctor.io', async () => 'oidc-token', scan, fetchImpl as typeof fetch, 0);
    expect(result).toEqual({ sent: true, message: 'Scan results saved for main.' });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe(`https://vibedoctor.io${SCAN_ROUTE}`);
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer oidc-token');
    expect(JSON.parse(init.body as string)).toEqual(scan);
  });

  it('names the scan results in its own replies', async () => {
    const send = (...responses: Array<Response | Error>) => sendScan('https://x.test', async () => 't', scan, fakeFetch(...responses) as typeof fetch, 0);
    expect((await send(new Response(null, { status: 204 }))).message).toBe('Scan results sent to VibeDoctor.');
    expect((await send(json(404, { message: 'acme/shop is not a project in VibeDoctor.' }))).message)
      .toBe('VibeDoctor did not accept the scan results (HTTP 404): acme/shop is not a project in VibeDoctor.');
    expect((await send(json(503, {}), json(503, {}))).message).toBe('Could not reach VibeDoctor (HTTP 503). Scan results were not sent; this job is not affected.');
    expect((await sendScan('http://x.test', async () => 't', scan, fakeFetch() as typeof fetch, 0)).message)
      .toBe('api-url must use https (got http://x.test). Scan results were not sent.');
  });
});
