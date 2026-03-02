/**
 * http-request-builder.ts
 * Centralizes HTTP request component parsing for the Presence Scan Engine.
 *
 * Guarantees:
 *   - Request line path is ALWAYS just pathname+search (never a full URL).
 *   - Host header is hostname[:port] only (no scheme).
 *   - Handles inputs with/without scheme, with explicit ports.
 *
 * Usage:
 *   const c = parseRequestComponents('target-service.example.com/test/actuator/heapdump');
 *   // { scheme:'https', host:'target-service.example.com', port:443,
 *   //   hostHeader:'target-service.example.com',
 *   //   pathWithQuery:'/test/actuator/heapdump',
 *   //   canonicalUrl:'https://target-service.example.com' }
 */

export interface RequestComponents {
    /** http or https */
    scheme: 'http' | 'https';
    /** bare hostname, no port */
    host: string;
    /** numeric port */
    port: number;
    /** "hostname" or "hostname:port" — use in HTTP Host header */
    hostHeader: string;
    /** path + query string, always starts with "/" */
    pathWithQuery: string;
    /** origin only: scheme://host[:port] — use as base when building candidate URLs */
    canonicalUrl: string;
}

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443 };

/**
 * Sanitize raw input before parsing:
 *  - Trim whitespace and surrounding quotes
 *  - Collapse accidental double-scheme "http://http://"
 *  - Add https:// if no scheme present
 */
function sanitize(raw: string): string {
    let s = raw.trim().replace(/^['"]|['"]$/g, '');

    // Collapse double scheme (e.g. "http://https://foo.com" → "https://foo.com")
    s = s.replace(/^https?:\/\/https?:\/\//i, 'https://');

    // If no scheme, add https:// — detect by absence of "://"
    if (!/^https?:\/\//i.test(s)) {
        // host:port pattern like "example.com:8080/foo"
        const hostPortPath = s.match(/^([^/]+):(\d{1,5})(\/.*)?$/);
        if (hostPortPath) {
            const port = parseInt(hostPortPath[2]);
            const scheme = (port === 443 || port === 8443) ? 'https' : 'http';
            s = `${scheme}://${s}`;
        } else {
            s = `https://${s}`;
        }
    }

    return s;
}

/**
 * Parse a raw target string (FQDN, URL with or without scheme/port/path)
 * into canonical HTTP request components.
 *
 * Throws if the result is not parseable as a URL even after sanitization.
 */
export function parseRequestComponents(raw: string): RequestComponents {
    const sanitized = sanitize(raw);

    let u: URL;
    try {
        u = new URL(sanitized);
    } catch {
        throw new Error(`Cannot parse target "${raw}" as URL (sanitized: "${sanitized}")`);
    }

    const scheme = (u.protocol.replace(':', '').toLowerCase() === 'http' ? 'http' : 'https') as 'http' | 'https';
    const host = u.hostname.toLowerCase();
    const defaultPort = DEFAULT_PORTS[scheme];
    const port = u.port ? parseInt(u.port) : defaultPort;
    const isNonDefaultPort = port !== defaultPort;
    const hostHeader = isNonDefaultPort ? `${host}:${port}` : host;

    // Build pathWithQuery — ensure it starts with "/"
    let pathWithQuery = u.pathname || '/';
    if (u.search) pathWithQuery += u.search;
    // Collapse double leading slashes
    pathWithQuery = pathWithQuery.replace(/^\/+/, '/');
    if (!pathWithQuery) pathWithQuery = '/';

    const canonicalUrl = isNonDefaultPort
        ? `${scheme}://${host}:${port}`
        : `${scheme}://${host}`;

    return { scheme, host, port, hostHeader, pathWithQuery, canonicalUrl };
}

/**
 * Build a safe candidate request from:
 *  - baseComponents: parsed origin (from ParsedTarget)
 *  - rawPath: the path from a TTP template or entrypoint hint
 *    → may be a full URL (must extract only the pathname), a bare path ("/api/v1/foo"),
 *      or a path with template variables already filled.
 *
 * Returns { method, fullUrl, pathWithQuery, hostHeader, scheme, port }
 */
export interface BuiltRequest {
    method: string;
    /** Full URL for Burp MCP url field (scheme://host[:port]/path?query) */
    fullUrl: string;
    /** Just path+query — for the HTTP request line */
    pathWithQuery: string;
    /** Bare hostname without port */
    host: string;
    hostHeader: string;
    scheme: string;
    port: number;
    headers: Record<string, string>;
}

export function buildSafeRequest(
    method: string,
    base: RequestComponents,
    rawPath: string,
    extraHeaders: Record<string, string> = {}
): BuiltRequest {
    // If rawPath looks like a full URL, extract only the path from it
    let pathWithQuery: string;
    if (/^https?:\/\//i.test(rawPath)) {
        try {
            const parsed = new URL(rawPath);
            pathWithQuery = parsed.pathname + parsed.search || '/';
        } catch {
            pathWithQuery = '/';
        }
    } else {
        // Bare path — ensure leading slash, collapse doubles
        pathWithQuery = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;
        pathWithQuery = pathWithQuery.replace(/^\/+/, '/');
        if (!pathWithQuery) pathWithQuery = '/';
    }

    const fullUrl = `${base.canonicalUrl}${pathWithQuery}`;

    const headers: Record<string, string> = {
        'Host': base.hostHeader,
        'User-Agent': 'PenPard/1.0',
        ...extraHeaders,
    };

    return {
        method: method.toUpperCase(),
        fullUrl,
        pathWithQuery,
        host: base.host,
        hostHeader: base.hostHeader,
        scheme: base.scheme,
        port: base.port,
        headers,
    };
}

/**
 * Format a human-readable request line for logging/display:
 * "GET /path HTTP/1.1\nHost: hostname\n..."
 */
export function formatRequestLine(req: BuiltRequest): string {
    const headerLines = Object.entries(req.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
    return `${req.method} ${req.pathWithQuery} HTTP/1.1\n${headerLines}`;
}

// ── User-Agent pool ──
// Small static list of realistic desktop browser UAs.
// Selection is seeded by runId so all requests within one run use the same UA.

const UA_POOL: string[] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
];

/**
 * Select a User-Agent that is stable for the lifetime of one scan run.
 * Uses a simple hash of the runId to pick consistently from the pool.
 */
export function selectRunUA(runId: string): string {
    let hash = 0;
    for (let i = 0; i < runId.length; i++) {
        hash = (hash * 31 + runId.charCodeAt(i)) >>> 0;
    }
    return UA_POOL[hash % UA_POOL.length];
}

/**
 * Build a browser-realistic header set for a GET/HEAD/OPTIONS request.
 * All values are typical for a desktop Chrome browser on Windows.
 */
export function browserHeaders(hostHeader: string, userAgent: string): Record<string, string> {
    return {
        'Host': hostHeader,
        'User-Agent': userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
    };
}

// ── Redirect chain type ──

export interface RedirectHop {
    fromUrl: string;
    toUrl: string;
    statusCode: number;
}

// ── Self-verifying test cases (runs at module load in development) ──

/* istanbul ignore next */
function runSelfTests(): void {
    const cases: Array<{ input: string; expectPath: string; expectHost: string; expectScheme: string; note: string }> = [
        {
            input: 'https://target-service.example.com/test/actuator/heapdump',
            expectPath: '/test/actuator/heapdump',
            expectHost: 'target-service.example.com',
            expectScheme: 'https',
            note: 'Full HTTPS URL with path',
        },
        {
            input: 'target-service.example.com/test/actuator/heapdump',
            expectPath: '/test/actuator/heapdump',
            expectHost: 'target-service.example.com',
            expectScheme: 'https',
            note: 'No scheme, path present — defaults to https',
        },
        {
            input: 'http://example.com',
            expectPath: '/',
            expectHost: 'example.com',
            expectScheme: 'http',
            note: 'HTTP with no path',
        },
        {
            input: 'example.com:8080/api/ping?x=1',
            expectPath: '/api/ping?x=1',
            expectHost: 'example.com:8080',
            expectScheme: 'http',
            note: 'host:port/path with query, non-default port → http',
        },
        {
            input: 'example.com:8443/api',
            expectPath: '/api',
            expectHost: 'example.com:8443',
            expectScheme: 'https',
            note: 'port 8443 → https',
        },
        {
            input: 'https://example.com:443/foo',
            expectPath: '/foo',
            expectHost: 'example.com',  // port 443 is default for https → omit from host header
            expectScheme: 'https',
            note: 'Explicit default port omitted from Host header',
        },
    ];

    let passed = 0;
    let failed = 0;
    const failures: string[] = [];

    for (const tc of cases) {
        try {
            const c = parseRequestComponents(tc.input);
            const pathOk = c.pathWithQuery === tc.expectPath;
            const hostOk = c.hostHeader === tc.expectHost;
            const schemeOk = c.scheme === tc.expectScheme;

            if (pathOk && hostOk && schemeOk) {
                passed++;
            } else {
                failed++;
                const details: string[] = [];
                if (!pathOk) details.push(`path: got "${c.pathWithQuery}", want "${tc.expectPath}"`);
                if (!hostOk) details.push(`host: got "${c.hostHeader}", want "${tc.expectHost}"`);
                if (!schemeOk) details.push(`scheme: got "${c.scheme}", want "${tc.expectScheme}"`);
                failures.push(`FAIL [${tc.note}]: ${details.join('; ')}`);
            }
        } catch (e: any) {
            failed++;
            failures.push(`FAIL [${tc.note}]: threw ${e.message}`);
        }
    }

    if (failed > 0) {
        // Log to stderr so it's visible in server startup — not a crash, just a warning
        console.error(`[http-request-builder] Self-test: ${passed} passed, ${failed} FAILED:`);
        failures.forEach(f => console.error('  ' + f));
    } else {
        console.log(`[http-request-builder] Self-test: ${passed}/${cases.length} passed OK`);
    }
}

// Run self-tests at module load (omit in production via NODE_ENV check if needed)
if (process.env.NODE_ENV !== 'test') {
    runSelfTests();
}
