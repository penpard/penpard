/**
 * Presence Scan Agent — Hypothesis-driven per-target presence checking.
 * Supports multiple TTPs per run: checks each target against each TTP.
 */

import { BurpMCPClient } from '../services/burp-mcp';
import { logger } from '../utils/logger';
import {
    getTTPById,
    updatePresenceScanRun,
    addPresenceScanTarget,
    updatePresenceScanTarget,
    getPresenceScanTargets,
    addPresenceScanLog,
} from '../db/init';
import type { ParsedTarget } from '../services/target-parser';
import {
    parseRequestComponents,
    buildSafeRequest,
    formatRequestLine,
    selectRunUA,
    browserHeaders,
    type RedirectHop,
} from '../services/http-request-builder';

// ── Types ──

export type Verdict = 'present' | 'likely' | 'absent' | 'unknown';

interface TTPCheckResult {
    ttpId: string;
    ttpTitle: string;
    verdict: Verdict;
    reason: string;
    matchedCriteria: string[];
    requestSent: string;
    responseExcerpt: string;
    evidence: { criterion: string; matched: boolean }[];
    redirectChain: RedirectHop[];
}

// Aggregate multiple TTP verdicts for a single target into one merged verdict
function mergeVerdicts(results: TTPCheckResult[]): { verdict: Verdict; reason: string } {
    if (results.some(r => r.verdict === 'present')) return { verdict: 'present', reason: results.find(r => r.verdict === 'present')!.reason };
    if (results.some(r => r.verdict === 'likely')) return { verdict: 'likely', reason: results.find(r => r.verdict === 'likely')!.reason };
    if (results.every(r => r.verdict === 'unknown')) return { verdict: 'unknown', reason: 'All TTP checks returned unknown' };
    return { verdict: 'absent', reason: 'No TTP criteria matched' };
}

/**
 * Extract a named header value from a raw HTTP response text body.
 * Used as a fallback when Burp MCP does not return parsed headers.
 */
function extractHeader(rawBody: string, headerName: string): string | undefined {
    const pattern = new RegExp(`^${headerName}:\\s*(.+)$`, 'im');
    const match = rawBody.match(pattern);
    return match ? match[1].trim() : undefined;
}

// ── Agent ──

export class PresenceScanAgent {
    private runId: string;
    private burp: BurpMCPClient;
    private isRunning = true;
    /** Single User-Agent chosen once at construction; reused for all requests in this run. */
    private readonly userAgent: string;
    private readonly REQUEST_TIMEOUT_MS = 15000;
    private readonly MIN_DELAY_MS = 1200;
    private readonly MAX_REDIRECTS = 5;

    constructor(runId: string) {
        this.runId = runId;
        this.burp = new BurpMCPClient();
        // Stable UA selection seeded by runId — consistent across all requests in this run
        this.userAgent = selectRunUA(runId);
    }

    // ── Main ──

    async run(ttpIds: string[], targets: ParsedTarget[]): Promise<void> {
        // Load all TTPs
        const ttps = ttpIds.map(id => getTTPById(id)).filter(Boolean);
        if (ttps.length === 0) {
            this.log('ERROR: No valid TTPs found');
            updatePresenceScanRun(this.runId, { status: 'failed', error_message: 'No valid TTPs found', finished_at: new Date().toISOString() });
            return;
        }

        this.log(`Starting presence scan — ${ttps.length} TTP(s) × ${targets.length} target(s)`);

        const burpAvailable = await this.burp.isAvailable();
        if (!burpAvailable) {
            this.log('WARNING: Burp MCP unavailable — all targets will receive verdict "unknown"');
        }

        // Insert all targets as pending
        for (const target of targets) {
            addPresenceScanTarget({
                runId: this.runId,
                targetRaw: target.raw,
                targetUrl: target.url,
                targetHost: target.host,
                targetPort: target.port,
                targetScheme: target.scheme,
            });
        }

        let present = 0, likely = 0, absent = 0, unknown = 0;
        const dbTargets = getPresenceScanTargets(this.runId);

        for (let i = 0; i < dbTargets.length; i++) {
            if (!this.isRunning) {
                this.log('Scan stopped by user request');
                break;
            }

            const dbTarget = dbTargets[i];
            const target = targets[i];

            updatePresenceScanTarget(dbTarget.id, { status: 'running' });
            this.log(`[${i + 1}/${targets.length}] Target: ${target.url}`);

            // Check against all TTPs
            const ttpResults: TTPCheckResult[] = [];

            for (const ttp of ttps) {
                if (!this.isRunning) break;

                this.log(`  → Checking TTP: "${ttp.title}"`);

                let result: TTPCheckResult;
                if (!burpAvailable) {
                    result = {
                        ttpId: ttp.id,
                        ttpTitle: ttp.title,
                        verdict: 'unknown',
                        reason: 'Burp MCP unavailable',
                        matchedCriteria: [],
                        requestSent: '',
                        responseExcerpt: '',
                        evidence: [],
                        redirectChain: [],
                    };
                } else {
                    result = await this.checkTargetWithTTP(target, ttp);
                }

                ttpResults.push(result);
                this.log(`    ${result.verdict.toUpperCase()}: ${result.reason}`);
            }

            // Merge verdicts from all TTPs
            const { verdict, reason } = mergeVerdicts(ttpResults);

            // Best evidence: from the highest-signal TTP result
            const bestResult = ttpResults.find(r => r.verdict === verdict) || ttpResults[0];

            updatePresenceScanTarget(dbTarget.id, {
                status: verdict,
                verdict,
                verdict_reason: reason,
                // Store per-TTP breakdown in evidence_json
                evidence_json: JSON.stringify({
                    per_ttp: ttpResults.map(r => ({
                        ttp_id: r.ttpId,
                        ttp_title: r.ttpTitle,
                        verdict: r.verdict,
                        reason: r.reason,
                        matched_criteria: r.matchedCriteria,
                        evidence: r.evidence,
                    })),
                }),
                request_sent: bestResult?.requestSent || '',
                response_excerpt: bestResult?.responseExcerpt || '',
                checked_at: new Date().toISOString(),
            });

            if (verdict === 'present') present++;
            else if (verdict === 'likely') likely++;
            else if (verdict === 'absent') absent++;
            else unknown++;

            updatePresenceScanRun(this.runId, {
                results_present: present,
                results_likely: likely,
                results_absent: absent,
                results_unknown: unknown,
            });

            if (i < targets.length - 1) await this.delay(this.MIN_DELAY_MS);
        }

        const finalStatus = this.isRunning ? 'completed' : 'stopped';
        updatePresenceScanRun(this.runId, {
            status: finalStatus,
            finished_at: new Date().toISOString(),
            results_present: present,
            results_likely: likely,
            results_absent: absent,
            results_unknown: unknown,
        });

        this.log(`Scan ${finalStatus}. Present:${present} Likely:${likely} Absent:${absent} Unknown:${unknown}`);
    }

    // ── Per-target × per-TTP check ──

    private async checkTargetWithTTP(target: ParsedTarget, ttp: any): Promise<TTPCheckResult> {
        const requestTemplates = ttp.request_templates_json ? JSON.parse(ttp.request_templates_json) : [];
        const entrypointHints = ttp.entrypoint_hints_json ? JSON.parse(ttp.entrypoint_hints_json) : {};
        const verificationCriteria: string[] = ttp.verification_criteria_json ? JSON.parse(ttp.verification_criteria_json) : [];

        const candidateUrls = this.buildCandidateUrls(target, requestTemplates, entrypointHints);
        const allEvidence: { criterion: string; matched: boolean }[] = verificationCriteria.map(c => ({ criterion: c, matched: false }));
        let bestRequestSent = '';
        let bestResponseExcerpt = '';
        let bestRedirectChain: RedirectHop[] = [];
        let totalMatched = 0;

        for (const candidate of candidateUrls.slice(0, 5)) {
            if (!this.isRunning) break;
            try {
                const { requestSent, responseBody, statusCode, responseRaw, redirectChain, outOfScope } =
                    await this.sendSafeRequest(candidate, candidate.host);

                if (outOfScope) {
                    // Redirect led outside target scope — mark unknown with redirect chain in evidence
                    return {
                        ttpId: ttp.id, ttpTitle: ttp.title,
                        verdict: 'unknown',
                        reason: `Redirect out of scope after ${redirectChain.length} hop(s)`,
                        matchedCriteria: [],
                        requestSent,
                        responseExcerpt: responseRaw.substring(0, 1000),
                        evidence: allEvidence,
                        redirectChain,
                    };
                }

                if (!bestRequestSent) {
                    bestRequestSent = requestSent;
                    bestResponseExcerpt = responseRaw.substring(0, 1000);
                    bestRedirectChain = redirectChain;
                }

                const matched = this.scoreCriteria(verificationCriteria, statusCode, responseBody, candidate.fullUrl);
                const matchCount = matched.filter(Boolean).length;
                if (matchCount > totalMatched) {
                    totalMatched = matchCount;
                    bestRequestSent = requestSent;
                    bestResponseExcerpt = responseRaw.substring(0, 1000);
                    bestRedirectChain = redirectChain;
                    matched.forEach((m, idx) => { if (idx < allEvidence.length) allEvidence[idx].matched = m; });
                }
            } catch (error: any) {
                const msg = error.message || '';
                if (/ENOTFOUND|ECONNREFUSED|timeout/i.test(msg)) {
                    return {
                        ttpId: ttp.id, ttpTitle: ttp.title,
                        verdict: 'unknown', reason: `Network error: ${msg.substring(0, 80)}`,
                        matchedCriteria: [], requestSent: bestRequestSent, responseExcerpt: '', evidence: allEvidence,
                        redirectChain: [],
                    };
                }
            }
            await this.delay(400);
        }

        const result = this.buildVerdict(totalMatched, verificationCriteria.length, allEvidence, bestRequestSent, bestResponseExcerpt);
        return { ttpId: ttp.id, ttpTitle: ttp.title, redirectChain: bestRedirectChain, ...result };
    }

    // ── URL building ──
    //
    // All candidate URLs are derived via parseRequestComponents + buildSafeRequest,
    // which guarantees the HTTP request line contains ONLY the path, never a full URL.

    private buildCandidateUrls(
        target: ParsedTarget,
        requestTemplates: any[],
        entrypointHints: { endpoints?: string[]; params?: string[] }
    ): ReturnType<typeof buildSafeRequest>[] {
        // Parse the target once into its canonical components
        let baseComponents;
        try {
            baseComponents = parseRequestComponents(target.url);
        } catch (e: any) {
            this.log(`WARN: Cannot parse target URL "${target.url}": ${e.message}`);
            return [];
        }

        const candidates: ReturnType<typeof buildSafeRequest>[] = [];
        const seen = new Set<string>();

        const addCandidate = (method: string, rawPath: string, extraHeaders: Record<string, string> = {}) => {
            if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) return;
            try {
                // Build browser-realistic headers; extraHeaders may override specific values
                const hdrs = { ...browserHeaders(baseComponents.hostHeader, this.userAgent), ...extraHeaders };
                const req = buildSafeRequest(method, baseComponents, rawPath, hdrs);
                if (!seen.has(req.fullUrl)) {
                    seen.add(req.fullUrl);
                    candidates.push(req);
                }
            } catch (e: any) {
                this.log(`WARN: Skipping candidate (${e.message})`);
            }
        };

        // From TTP request templates
        for (const tmpl of requestTemplates) {
            if (!tmpl.path) continue;
            const method = (tmpl.method || 'GET').toUpperCase();
            const path = this.fillPathVariables(tmpl.path, baseComponents);
            // Build extra headers from template (excluding Host — we set it correctly)
            const extraHeaders = this.parseTemplateHeaders(tmpl.headers || []);
            addCandidate(method, path, extraHeaders);
        }

        // From entrypoint hints
        for (const endpoint of (entrypointHints.endpoints || []).slice(0, 3)) {
            const path = this.fillPathVariables(endpoint, baseComponents);
            addCandidate('GET', path);
        }

        // Fallback: root path
        if (candidates.length === 0) {
            addCandidate('GET', '/');
        }

        return candidates;
    }

    // Fill {host}, {port}, {scheme}, {id}, etc. placeholders in path templates.
    // NOTE: target here is RequestComponents (not ParsedTarget) to keep types tidy.
    private fillPathVariables(path: string, base: ReturnType<typeof parseRequestComponents>): string {
        return path
            .replace(/\{host\}/g, base.host)
            .replace(/\{scheme\}/g, base.scheme)
            .replace(/\{port\}/g, String(base.port))
            .replace(/\{id\}/g, '1')
            .replace(/\{user_?id\}/g, '1')
            .replace(/\{uuid\}/g, '00000000-0000-0000-0000-000000000001')
            .replace(/\{[^}]+\}/g, 'test');
    }

    // Parse template headers array/object; strips Host (we supply it via buildSafeRequest).
    private parseTemplateHeaders(headersTmpl: string[] | Record<string, string>): Record<string, string> {
        const out: Record<string, string> = {};
        if (Array.isArray(headersTmpl)) {
            for (const h of headersTmpl) {
                const [k, ...vParts] = h.split(':');
                if (k && vParts.length) out[k.trim()] = vParts.join(':').trim();
            }
        } else if (typeof headersTmpl === 'object') {
            Object.assign(out, headersTmpl);
        }
        // Remove Host — buildSafeRequest sets it correctly
        delete out['Host'];
        delete out['host'];
        return out;
    }

    // ── HTTP sender with redirect following ──
    //
    // Follows 301/302/303/307/308 up to MAX_REDIRECTS hops.
    // Stops and marks unknown if redirected to an out-of-scope host.
    // Stores the full redirect chain in the returned evidence.

    private async sendSafeRequest(
        req: ReturnType<typeof buildSafeRequest>,
        originalHost?: string
    ): Promise<{
        requestSent: string;
        responseBody: string;
        statusCode: number;
        responseRaw: string;
        redirectChain: RedirectHop[];
        outOfScope: boolean;
    }> {
        const redirectChain: RedirectHop[] = [];
        const visitedUrls = new Set<string>();
        const allowedHost = originalHost ?? req.host;

        let current = req;
        let lastStatusCode = 0;
        let lastResponseBody = '';
        let lastResponseRaw = '';
        let firstRequestSent = '';

        for (let hop = 0; hop <= this.MAX_REDIRECTS; hop++) {
            if (!this.isRunning) break;

            const requestSent = formatRequestLine(current);
            if (hop === 0) firstRequestSent = requestSent;

            this.log(`    [hop ${hop}] ${current.method} ${current.pathWithQuery} → ${current.hostHeader}`);

            if (visitedUrls.has(current.fullUrl)) {
                this.log(`    Loop detected at ${current.fullUrl} — stopping redirect chain`);
                break;
            }
            visitedUrls.add(current.fullUrl);

            let result: any;
            try {
                result = await Promise.race([
                    this.burp.callTool('send_http_request', {
                        url: current.fullUrl,
                        host: current.host,
                        port: current.port,
                        scheme: current.scheme,
                        path: current.pathWithQuery,
                        method: current.method,
                        headers: current.headers,
                        body: '',
                    }),
                    new Promise<never>((_, reject) =>
                        setTimeout(() => reject(new Error('Request timeout')), this.REQUEST_TIMEOUT_MS)
                    ),
                ]);
            } catch (err: any) {
                throw err; // propagate — caller handles ENOTFOUND/timeout
            }

            lastStatusCode = result?.statusCode || result?.status || 0;
            lastResponseBody = (result?.body || result?.responseBody || '').substring(0, 4000);
            lastResponseRaw = `HTTP/1.1 ${lastStatusCode}\n${lastResponseBody}`;

            const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
            if (!REDIRECT_CODES.has(lastStatusCode)) break; // not a redirect — done
            if (hop === this.MAX_REDIRECTS) {
                this.log(`    Max redirect depth (${this.MAX_REDIRECTS}) reached`);
                break;
            }

            // Extract Location header
            const locationRaw: string | undefined =
                result?.headers?.location ||
                result?.responseHeaders?.location ||
                result?.headers?.Location ||
                result?.responseHeaders?.Location ||
                extractHeader(lastResponseBody, 'location');

            if (!locationRaw) {
                this.log(`    Redirect ${lastStatusCode} with no Location header — stopping`);
                break;
            }

            // Resolve relative Location against current URL
            let nextUrl: string;
            try {
                nextUrl = new URL(locationRaw, current.fullUrl).toString();
            } catch {
                this.log(`    Cannot parse redirect Location: ${locationRaw}`);
                break;
            }

            redirectChain.push({ fromUrl: current.fullUrl, toUrl: nextUrl, statusCode: lastStatusCode });
            this.log(`    Redirect ${lastStatusCode}: ${current.fullUrl} → ${nextUrl}`);

            // Parse next URL
            let nextComponents;
            try {
                nextComponents = parseRequestComponents(nextUrl);
            } catch {
                this.log(`    Cannot parse redirect target: ${nextUrl}`);
                break;
            }

            // Scope check — only follow redirects within the same registered host
            if (nextComponents.host !== allowedHost) {
                this.log(`    Redirect out of scope: ${nextComponents.host} (allowed: ${allowedHost}) — stopping`);
                redirectChain[redirectChain.length - 1].toUrl += ' [out-of-scope]';
                // Return with outOfScope flag so caller can decide verdict
                return {
                    requestSent: firstRequestSent,
                    responseBody: lastResponseBody,
                    statusCode: lastStatusCode,
                    responseRaw: lastResponseRaw,
                    redirectChain,
                    outOfScope: true,
                };
            }

            // Method semantics: 303 and 301/302 with non-GET → downgrade to GET
            const nextMethod = (lastStatusCode === 307 || lastStatusCode === 308)
                ? current.method
                : 'GET';

            // Build next request with browser headers for the new host
            const nextHeaders = browserHeaders(nextComponents.hostHeader, this.userAgent);
            current = buildSafeRequest(nextMethod, nextComponents, nextComponents.pathWithQuery, nextHeaders);
        }

        return {
            requestSent: firstRequestSent,
            responseBody: lastResponseBody,
            statusCode: lastStatusCode,
            responseRaw: lastResponseRaw,
            redirectChain,
            outOfScope: false,
        };
    }

    // ── Scoring ──

    private scoreCriteria(criteria: string[], statusCode: number, responseBody: string, url: string): boolean[] {
        return criteria.map(criterion => {
            const c = criterion.toLowerCase();
            const body = responseBody.toLowerCase();

            if (/http\s*200/.test(c) && statusCode === 200) return true;
            if (/200\s+instead\s+of\s+403/.test(c) && statusCode === 200) return true;
            if (/403/.test(c) && statusCode === 403) return true;
            if (/401/.test(c) && statusCode === 401) return true;
            if (/500/.test(c) && statusCode === 500) return true;
            if (/sql\s+error|syntax\s+error|mysql|ora-\d/.test(c) && /sql.*error|syntax.*error|mysql|ora-\d/i.test(responseBody)) return true;
            if (/other\s+user|another\s+user|different\s+user/.test(c) && /user_?id['"\s:]+\d+/.test(body)) return true;
            if (/xss|script/.test(c) && /<script>/i.test(responseBody)) return true;
            if (/path\s+traversal|etc\/passwd/.test(c) && /root:/i.test(responseBody)) return true;
            if (/redirect|location/.test(c) && /location:/i.test(responseBody)) return true;

            const keyword = c.replace(/[^a-z0-9\s]/g, '').trim().split(/\s+/)[0];
            if (keyword && keyword.length > 4 && body.includes(keyword)) return true;

            return false;
        });
    }

    private buildVerdict(
        matchCount: number,
        totalCriteria: number,
        evidence: { criterion: string; matched: boolean }[],
        requestSent: string,
        responseExcerpt: string
    ): { verdict: Verdict; reason: string; matchedCriteria: string[]; requestSent: string; responseExcerpt: string; evidence: typeof evidence } {
        const matchedCriteria = evidence.filter(e => e.matched).map(e => e.criterion);
        if (totalCriteria === 0) return { verdict: 'unknown', reason: 'No verification criteria defined', matchedCriteria: [], requestSent, responseExcerpt, evidence };
        if (matchCount >= 2 || (totalCriteria === 1 && matchCount === 1)) return { verdict: 'present', reason: `${matchCount}/${totalCriteria} criteria matched`, matchedCriteria, requestSent, responseExcerpt, evidence };
        if (matchCount === 1) return { verdict: 'likely', reason: `1/${totalCriteria} criteria matched (partial)`, matchedCriteria, requestSent, responseExcerpt, evidence };
        if (!requestSent) return { verdict: 'unknown', reason: 'No requests were sent', matchedCriteria: [], requestSent, responseExcerpt, evidence };
        return { verdict: 'absent', reason: `0/${totalCriteria} criteria matched`, matchedCriteria: [], requestSent, responseExcerpt, evidence };
    }

    // ── Control ──

    stop(): void {
        this.isRunning = false;
        this.log('Stop signal received');
    }

    private log(message: string): void {
        const ts = new Date().toISOString().substring(11, 19);
        addPresenceScanLog(this.runId, `[${ts}] ${message}`);
        logger.info(message, { runId: this.runId });
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// ── In-memory agent registry ──

const activeAgents = new Map<string, PresenceScanAgent>();
export const registerPresenceScanAgent = (runId: string, agent: PresenceScanAgent) => activeAgents.set(runId, agent);
export const getPresenceScanAgent = (runId: string) => activeAgents.get(runId);
export const removePresenceScanAgent = (runId: string) => activeAgents.delete(runId);
