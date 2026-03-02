/**
 * Presence Scan Routes — REST API for the Presence Scan Engine
 * Supports multiple TTPs per scan run (ttp_ids[]) with backward compat (ttp_id).
 */

import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';
import {
    createPresenceScanRun,
    getPresenceScanRun,
    getUserPresenceScanRuns,
    updatePresenceScanRun,
    getPresenceScanTargets,
    getPresenceScanLogs,
    deletePresenceScanRun,
    getTTPById,
    addPresenceScanRunTTP,
    getPresenceScanRunTTPs,
} from '../db/init';
import { parseTargetList } from '../services/target-parser';
import {
    PresenceScanAgent,
    registerPresenceScanAgent,
    getPresenceScanAgent,
    removePresenceScanAgent,
} from '../agents/presence-scan-agent';

const router = Router();

// ══════════════════════════════════════════════════════
// POST /api/presence-scan/runs — Create and start a run
// Body: { ttp_ids: string[], targets_raw: string, targets_format?: string }
// Backward compat: ttp_id (singular) → ttp_ids = [ttp_id]
// ══════════════════════════════════════════════════════

router.post('/runs', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const {
            ttp_id,          // legacy single-TTP support
            ttp_ids: rawIds,
            targets_raw,
            targets_format,
        } = req.body;

        // Normalize ttp_ids
        let ttpIds: string[] = [];
        if (Array.isArray(rawIds) && rawIds.length > 0) {
            ttpIds = rawIds.filter(Boolean);
        } else if (ttp_id) {
            ttpIds = [ttp_id];
        }

        if (ttpIds.length === 0) {
            return res.status(400).json({ error: true, message: 'Provide at least one ttp_id or ttp_ids array' });
        }
        if (!targets_raw || typeof targets_raw !== 'string' || !targets_raw.trim()) {
            return res.status(400).json({ error: true, message: 'targets_raw is required (JSON, CSV, or TXT)' });
        }

        // Validate all TTPs
        const ttps = ttpIds.map(id => getTTPById(id)).filter(Boolean);
        if (ttps.length !== ttpIds.length) {
            return res.status(404).json({ error: true, message: 'One or more TTP IDs not found' });
        }
        const inactiveTTPs = ttps.filter(t => !t.is_active);
        if (inactiveTTPs.length > 0) {
            return res.status(400).json({
                error: true,
                message: `TTP(s) are inactive: ${inactiveTTPs.map(t => t.title).join(', ')}`,
            });
        }

        // Parse targets
        const targets = parseTargetList(targets_raw, targets_format || 'auto');
        if (targets.length === 0) {
            return res.status(400).json({ error: true, message: 'No valid targets found in provided list' });
        }

        const runId = uuidv4();
        // Store run with first TTP as legacy ttp_id (for backward compat column)
        createPresenceScanRun({
            id: runId,
            userId: user.id,
            ttpId: ttpIds[0],
            ttpTitle: ttps.length === 1 ? ttps[0].title : `${ttps.length} TTPs`,
            targetsCount: targets.length,
        });

        // Store all TTP associations in join table
        for (const ttp of ttps) {
            addPresenceScanRunTTP(runId, ttp.id, ttp.title);
        }

        // Launch async agent
        const agent = new PresenceScanAgent(runId);
        registerPresenceScanAgent(runId, agent);

        agent.run(ttpIds, targets).finally(() => {
            removePresenceScanAgent(runId);
        }).catch((err: any) => {
            logger.error('Presence scan agent failed', { runId, error: err.message });
            updatePresenceScanRun(runId, {
                status: 'failed',
                error_message: err.message,
                finished_at: new Date().toISOString(),
            });
        });

        res.json({
            runId,
            targets_count: targets.length,
            ttp_count: ttpIds.length,
            ttp_titles: ttps.map(t => t.title),
            message: 'Presence scan started.',
        });

    } catch (error: any) {
        logger.error('Failed to create presence scan run', { error: error.message });
        res.status(500).json({ error: true, message: error.message });
    }
});

// ══════════════════════════════════════════════════════
// GET /api/presence-scan/runs — List user's runs
// ══════════════════════════════════════════════════════

router.get('/runs', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const runs = getUserPresenceScanRuns(req.user!.id);
        // Attach ttp list to each run
        const enriched = runs.map(run => ({
            ...run,
            ttps: getPresenceScanRunTTPs(run.id),
        }));
        res.json({ runs: enriched });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list runs' });
    }
});

// ══════════════════════════════════════════════════════
// GET /api/presence-scan/runs/:id — Run detail
// ══════════════════════════════════════════════════════

router.get('/runs/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const run = getPresenceScanRun(req.params.id);
        if (!run) return res.status(404).json({ error: true, message: 'Run not found' });
        if (run.user_id !== req.user!.id) return res.status(403).json({ error: true, message: 'Access denied' });
        res.json({ ...run, ttps: getPresenceScanRunTTPs(run.id) });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get run' });
    }
});

// ══════════════════════════════════════════════════════
// GET /api/presence-scan/runs/:id/results — Per-target results
// Query: ?verdict=present|likely|absent|unknown  &ttp_id=...  &page=1  &per_page=50
// ══════════════════════════════════════════════════════

router.get('/runs/:id/results', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const run = getPresenceScanRun(req.params.id);
        if (!run) return res.status(404).json({ error: true, message: 'Run not found' });
        if (run.user_id !== req.user!.id) return res.status(403).json({ error: true, message: 'Access denied' });

        const verdictFilter = req.query.verdict as string | undefined;
        const ttpIdFilter = req.query.ttp_id as string | undefined;
        const page = Math.max(1, parseInt(req.query.page as string) || 1);
        const perPage = Math.min(200, parseInt(req.query.per_page as string) || 50);

        let results = getPresenceScanTargets(run.id, verdictFilter);

        // Filter by TTP if requested
        if (ttpIdFilter) {
            results = results.filter(r => r.ttp_id === ttpIdFilter);
        }

        // Parse JSON columns
        results = results.map(r => ({
            ...r,
            evidence: r.evidence_json ? JSON.parse(r.evidence_json) : [],
        }));

        const total = results.length;
        const paginated = results.slice((page - 1) * perPage, page * perPage);

        res.json({ results: paginated, total, page, per_page: perPage });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get results' });
    }
});

// ══════════════════════════════════════════════════════
// GET /api/presence-scan/runs/:id/logs — Logs
// ══════════════════════════════════════════════════════

router.get('/runs/:id/logs', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const run = getPresenceScanRun(req.params.id);
        if (!run) return res.status(404).json({ error: true, message: 'Run not found' });
        if (run.user_id !== req.user!.id) return res.status(403).json({ error: true, message: 'Access denied' });
        res.json({ logs: getPresenceScanLogs(run.id) });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get logs' });
    }
});

// ══════════════════════════════════════════════════════
// POST /api/presence-scan/runs/:id/stop
// ══════════════════════════════════════════════════════

router.post('/runs/:id/stop', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const run = getPresenceScanRun(req.params.id);
        if (!run) return res.status(404).json({ error: true, message: 'Run not found' });
        if (run.user_id !== req.user!.id) return res.status(403).json({ error: true, message: 'Access denied' });
        if (run.status !== 'running') {
            return res.status(400).json({ error: true, message: `Run is already ${run.status}` });
        }
        const agent = getPresenceScanAgent(run.id);
        if (agent) agent.stop();
        res.json({ message: 'Stop signal sent' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to stop run' });
    }
});

// ══════════════════════════════════════════════════════
// DELETE /api/presence-scan/runs/:id
// ══════════════════════════════════════════════════════

router.delete('/runs/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const run = getPresenceScanRun(req.params.id);
        if (!run) return res.status(404).json({ error: true, message: 'Run not found' });
        if (run.user_id !== req.user!.id) return res.status(403).json({ error: true, message: 'Access denied' });
        const agent = getPresenceScanAgent(run.id);
        if (agent) { agent.stop(); removePresenceScanAgent(run.id); }
        deletePresenceScanRun(run.id, req.user!.id);
        res.json({ message: 'Run deleted' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to delete run' });
    }
});

export default router;
