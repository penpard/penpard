/**
 * Target Parser — Normalized target list parsing for Presence Scan Engine
 * Supports JSON, CSV, and TXT input formats.
 */

export interface ParsedTarget {
    raw: string;
    url: string;      // canonical URL (with scheme + host + port if non-standard)
    host: string;
    port: number;
    scheme: string;   // http | https
}

// ── Normalization ──

function normalizeTarget(raw: string): ParsedTarget | null {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) return null;

    let urlStr = trimmed;

    // Add scheme if missing
    if (!/^https?:\/\//i.test(urlStr)) {
        // Check for host:port pattern
        const colonPort = urlStr.match(/^([^:/]+):(\d+)(\/.*)?$/);
        if (colonPort) {
            const port = parseInt(colonPort[2]);
            const scheme = port === 443 || port === 8443 ? 'https' : 'http';
            urlStr = `${scheme}://${urlStr}`;
        } else {
            urlStr = `https://${urlStr}`;
        }
    }

    try {
        const u = new URL(urlStr);
        const scheme = u.protocol.replace(':', '');
        const defaultPort = scheme === 'https' ? 443 : 80;
        const port = u.port ? parseInt(u.port) : defaultPort;

        return {
            raw: trimmed,
            url: `${scheme}://${u.hostname}${u.port ? `:${u.port}` : ''}`,
            host: u.hostname,
            port,
            scheme,
        };
    } catch {
        return null; // unparseable
    }
}

// ── TXT parser ──

function parseTxt(raw: string): ParsedTarget[] {
    return raw
        .split(/\r?\n/)
        .map(line => normalizeTarget(line.trim()))
        .filter((t): t is ParsedTarget => t !== null);
}

// ── JSON parser ──

function parseJson(raw: string): ParsedTarget[] {
    let parsed: any;
    try { parsed = JSON.parse(raw); } catch { return []; }

    const items: string[] = [];

    if (Array.isArray(parsed)) {
        for (const item of parsed) {
            if (typeof item === 'string') {
                items.push(item);
            } else if (typeof item === 'object' && item !== null) {
                // Support {target, fqdn, url, host} keys
                const val = item.url || item.target || item.fqdn || item.host;
                if (val) items.push(String(val));
            }
        }
    }

    return items
        .map(s => normalizeTarget(s))
        .filter((t): t is ParsedTarget => t !== null);
}

// ── CSV parser ──

function parseCsv(raw: string): ParsedTarget[] {
    const lines = raw.split(/\r?\n/).filter(l => l.trim());
    if (!lines.length) return [];

    // Detect header row
    const firstLine = lines[0].toLowerCase();
    const hasHeader = /fqdn|url|host|target|domain/.test(firstLine);
    const headers = hasHeader
        ? firstLine.split(',').map(h => h.trim().replace(/^["']|["']$/g, ''))
        : ['fqdn'];

    const urlColCandidates = ['url', 'fqdn', 'host', 'target', 'domain'];
    const urlColIdx = headers.findIndex(h => urlColCandidates.includes(h));
    const effectiveColIdx = urlColIdx >= 0 ? urlColIdx : 0;

    const dataLines = hasHeader ? lines.slice(1) : lines;

    return dataLines
        .map(line => {
            const cols = line.split(',').map(c => c.trim().replace(/^["']|["']$/g, ''));
            const val = cols[effectiveColIdx];
            if (!val) return null;

            // If there are scheme/port columns, use them
            const schemeIdx = headers.findIndex(h => h === 'scheme');
            const portIdx = headers.findIndex(h => h === 'port');

            let target = val;
            if (schemeIdx >= 0 && cols[schemeIdx]) {
                target = `${cols[schemeIdx]}://${target}`;
            }
            if (portIdx >= 0 && cols[portIdx] && !target.includes(':' + cols[portIdx])) {
                target = `${target}:${cols[portIdx]}`;
            }

            return normalizeTarget(target);
        })
        .filter((t): t is ParsedTarget => t !== null);
}

// ── Auto-detect format ──

function detectFormat(raw: string): 'json' | 'csv' | 'txt' {
    const trimmed = raw.trim();
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) return 'json';
    if (trimmed.includes(',') && (trimmed.toLowerCase().includes('fqdn') || trimmed.toLowerCase().includes('url') || trimmed.toLowerCase().includes('host'))) return 'csv';
    return 'txt';
}

// ── Public API ──

export function parseTargetList(
    raw: string,
    formatHint?: 'json' | 'csv' | 'txt' | 'auto'
): ParsedTarget[] {
    const fmt = (!formatHint || formatHint === 'auto') ? detectFormat(raw) : formatHint;

    let targets: ParsedTarget[];
    switch (fmt) {
        case 'json': targets = parseJson(raw); break;
        case 'csv': targets = parseCsv(raw); break;
        default: targets = parseTxt(raw); break;
    }

    // Deduplicate by normalized URL
    const seen = new Set<string>();
    return targets.filter(t => {
        if (seen.has(t.url)) return false;
        seen.add(t.url);
        return true;
    });
}
