/**
 * Report Analysis Routes — Red Team Report Learning Engine
 * Upload, analyze, retrieve findings, TTPs, and mindset profile
 */

import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';
import {
    createAnalysis,
    getAnalysis,
    getUserAnalyses,
    updateAnalysisStatus,
    updateAnalysisMetadata,
    addAnalysisFinding,
    getAnalysisFindings,
    getAnalysisLogs,
    deleteAnalysis,
    getAllTTPs,
    getTTPById,
    getTTPsByAnalysis,
    toggleTTPActive,
    getMindsetProfile,
} from '../db/init';
import { reportParser } from '../services/report-parser';
import { ReportLearningAgent } from '../agents/RedTeamReconstructionAgent';

const router = Router();

// ── Multer setup for report uploads ──

const uploadsDir = path.join(__dirname, '../../uploads/reports');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: uploadsDir,
    filename(req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, `report-${uuidv4()}${ext}`);
    },
});

const upload = multer({
    storage,
    fileFilter(req, file, cb) {
        const allowedTypes = ['.pdf', '.docx'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF and DOCX files are allowed'));
        }
    },
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
});

// ══════════════════════════════════════════════════════
// REPORT UPLOAD & ANALYSIS
// ══════════════════════════════════════════════════════

router.post('/upload', authenticateToken, upload.single('report'), async (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const file = req.file;

        if (!file) {
            return res.status(400).json({ error: true, message: 'No report file uploaded' });
        }

        const analysisId = uuidv4();

        createAnalysis({
            id: analysisId,
            userId: user.id,
            filename: file.originalname,
            filePath: file.path,
        });

        // Start async analysis pipeline
        (async () => {
            try {
                updateAnalysisStatus(analysisId, 'parsing');

                // Step 1: Parse report
                const parsedReport = await reportParser.parseReport(file.path, analysisId);

                // Save metadata
                updateAnalysisMetadata(analysisId, JSON.stringify(parsedReport.report_metadata));

                // Save extracted findings to DB
                for (const finding of parsedReport.findings) {
                    addAnalysisFinding({
                        analysisId,
                        title: finding.title,
                        severity: finding.severity,
                        cvssScore: finding.cvss ? parseFloat(finding.cvss) : undefined,
                        cvssVector: finding.cvss && finding.cvss.includes('CVSS:') ? finding.cvss : undefined,
                        description: finding.description,
                        pocStepsJson: JSON.stringify(finding.poc_steps),
                        rawHttpRequestsJson: JSON.stringify(finding.raw_http_requests),
                        payloadsJson: JSON.stringify(finding.payloads),
                        evidenceJson: JSON.stringify(finding.evidence),
                        recommendation: finding.recommendation,
                    });
                }

                // Step 2: Run learning agent (TTP derivation + mindset profile)
                updateAnalysisStatus(analysisId, 'analyzing');
                const agent = new ReportLearningAgent(analysisId);
                await agent.analyze(parsedReport);

            } catch (error: any) {
                logger.error('Report analysis pipeline failed', { analysisId, error: error.message });
                updateAnalysisStatus(analysisId, 'failed', error.message);
            }
        })();

        res.json({
            analysisId,
            message: 'Report uploaded. Learning pipeline started.',
        });

    } catch (error: any) {
        logger.error('Report upload error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to upload report: ' + (error.message || '') });
    }
});

// ── List user's analyses ──

router.get('/', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const analyses = getUserAnalyses(user.id);
        res.json({ analyses });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list analyses' });
    }
});

// ── Get analysis status + results ──

router.get('/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);

        if (!analysis) return res.status(404).json({ error: true, message: 'Analysis not found' });
        if (analysis.user_id !== user.id) return res.status(403).json({ error: true, message: 'Access denied' });

        res.json({
            ...analysis,
            report_metadata: analysis.report_metadata_json ? JSON.parse(analysis.report_metadata_json) : null,
            behavioral_profile: analysis.behavioral_profile_json ? JSON.parse(analysis.behavioral_profile_json) : null,
        });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get analysis' });
    }
});

// ── Get analysis findings ──

router.get('/:id/findings', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });

        const findings = getAnalysisFindings(id).map(f => ({
            ...f,
            poc_steps: f.poc_steps_json ? JSON.parse(f.poc_steps_json) : [],
            raw_http_requests: f.raw_http_requests_json ? JSON.parse(f.raw_http_requests_json) : [],
            payloads: f.payloads_json ? JSON.parse(f.payloads_json) : [],
            evidence: f.evidence_json ? JSON.parse(f.evidence_json) : [],
            reasoning_chain: f.reasoning_chain_json ? JSON.parse(f.reasoning_chain_json) : [],
        }));

        res.json({ findings });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get findings' });
    }
});

// ── Get analysis logs ──

router.get('/:id/logs', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });
        res.json({ logs: getAnalysisLogs(id) });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get logs' });
    }
});

// ── Delete analysis ──

router.delete('/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });

        if (analysis.file_path && fs.existsSync(analysis.file_path)) {
            fs.unlinkSync(analysis.file_path);
        }
        deleteAnalysis(id, user.id);
        res.json({ message: 'Analysis deleted' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to delete analysis' });
    }
});

// ══════════════════════════════════════════════════════
// TTP LIBRARY
// ══════════════════════════════════════════════════════

// ── List all TTPs ──

router.get('/ttps/list', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const ttps = getAllTTPs().map(t => ({
            ...t,
            discovery_strategy: t.discovery_strategy_json ? JSON.parse(t.discovery_strategy_json) : [],
            preconditions: t.preconditions_json ? JSON.parse(t.preconditions_json) : {},
            entrypoint_hints: t.entrypoint_hints_json ? JSON.parse(t.entrypoint_hints_json) : {},
            request_templates: t.request_templates_json ? JSON.parse(t.request_templates_json) : [],
            payload_templates: t.payload_templates_json ? JSON.parse(t.payload_templates_json) : [],
            verification_criteria: t.verification_criteria_json ? JSON.parse(t.verification_criteria_json) : [],
        }));
        res.json({ ttps });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list TTPs' });
    }
});

// ── Get single TTP ──

router.get('/ttps/:ttpId', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const ttp = getTTPById(req.params.ttpId);
        if (!ttp) return res.status(404).json({ error: true, message: 'TTP not found' });
        res.json({
            ...ttp,
            discovery_strategy: ttp.discovery_strategy_json ? JSON.parse(ttp.discovery_strategy_json) : [],
            preconditions: ttp.preconditions_json ? JSON.parse(ttp.preconditions_json) : {},
            entrypoint_hints: ttp.entrypoint_hints_json ? JSON.parse(ttp.entrypoint_hints_json) : {},
            request_templates: ttp.request_templates_json ? JSON.parse(ttp.request_templates_json) : [],
            payload_templates: ttp.payload_templates_json ? JSON.parse(ttp.payload_templates_json) : [],
            verification_criteria: ttp.verification_criteria_json ? JSON.parse(ttp.verification_criteria_json) : [],
        });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get TTP' });
    }
});

// ── Toggle TTP active/inactive ──

router.patch('/ttps/:ttpId/toggle', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const ttp = getTTPById(req.params.ttpId);
        if (!ttp) return res.status(404).json({ error: true, message: 'TTP not found' });
        const newState = !ttp.is_active;
        toggleTTPActive(req.params.ttpId, newState);
        res.json({ message: `TTP ${newState ? 'activated' : 'deactivated'}`, is_active: newState });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to toggle TTP' });
    }
});

// ── Get mindset profile ──

router.get('/mindset-profile/current', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const profile = getMindsetProfile();
        res.json({
            profile: profile?.profile_json ? JSON.parse(profile.profile_json) : null,
            updated_at: profile?.updated_at || null,
        });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get mindset profile' });
    }
});

// ── Export analysis (without defensive data) ──

router.get('/:id/export', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });

        const findings = getAnalysisFindings(id).map(f => ({
            title: f.title,
            severity: f.severity,
            cvss_score: f.cvss_score,
            description: f.description,
            poc_steps: f.poc_steps_json ? JSON.parse(f.poc_steps_json) : [],
            raw_http_requests: f.raw_http_requests_json ? JSON.parse(f.raw_http_requests_json) : [],
            payloads: f.payloads_json ? JSON.parse(f.payloads_json) : [],
            recommendation: f.recommendation,
            discovery_method: f.discovery_method,
            reasoning_chain: f.reasoning_chain_json ? JSON.parse(f.reasoning_chain_json) : [],
        }));

        const ttps = getTTPsByAnalysis(id).map(t => ({
            id: t.id,
            title: t.title,
            vulnerability_class: t.vulnerability_class,
            discovery_strategy: t.discovery_strategy_json ? JSON.parse(t.discovery_strategy_json) : [],
            preconditions: t.preconditions_json ? JSON.parse(t.preconditions_json) : {},
            entrypoint_hints: t.entrypoint_hints_json ? JSON.parse(t.entrypoint_hints_json) : {},
            request_templates: t.request_templates_json ? JSON.parse(t.request_templates_json) : [],
            payload_templates: t.payload_templates_json ? JSON.parse(t.payload_templates_json) : [],
            verification_criteria: t.verification_criteria_json ? JSON.parse(t.verification_criteria_json) : [],
            confidence: t.confidence,
            generalization_notes: t.generalization_notes,
        }));

        const exportData = {
            analysis_id: analysis.id,
            filename: analysis.filename,
            status: analysis.status,
            created_at: analysis.created_at,
            report_metadata: analysis.report_metadata_json ? JSON.parse(analysis.report_metadata_json) : null,
            findings,
            learned_ttps: ttps,
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="penpard-learning-${id}.json"`);
        res.json(exportData);
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to export analysis' });
    }
});

export default router;
