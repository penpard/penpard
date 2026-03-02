'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Upload, FileSearch, Brain, ChevronDown, ChevronRight, AlertTriangle,
    CheckCircle, Clock, Loader2, Download, Trash2, ArrowLeft, Zap, Target,
    Activity, BarChart3, BookOpen, ToggleLeft, ToggleRight,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import toast from 'react-hot-toast';

// ── Types ──

interface Analysis {
    id: string;
    filename: string;
    status: string;
    report_metadata: any;
    behavioral_profile: any;
    created_at: string;
    completed_at: string;
    error_message?: string;
}

interface Finding {
    id: number;
    title: string;
    severity: string;
    cvss_score: number;
    description: string;
    poc_steps: string[];
    raw_http_requests: string[];
    payloads: string[];
    evidence: string[];
    recommendation: string;
    discovery_method: string;
    reasoning_chain: string[];
}

interface TTP {
    id: string;
    title: string;
    vulnerability_class: string;
    discovery_strategy: string[];
    preconditions: { auth?: boolean; roles?: string[]; notes?: string };
    entrypoint_hints: { endpoints?: string[]; params?: string[] };
    request_templates: { method: string; path: string; headers?: string[]; body?: string }[];
    payload_templates: { type: string; name: string; generator: string; constraints?: string }[];
    verification_criteria: string[];
    confidence: number;
    generalization_notes: string;
    is_active: number;
    source_analysis_id: string;
}

interface MindsetProfile {
    total_ttps: number;
    common_vuln_classes: { class: string; count: number }[];
    common_strategies: string[];
    sophistication_score: number;
    preferred_sequences: string[];
    updated_at: string;
}

// ── Helpers ──

const severityColor: Record<string, string> = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/20',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    info: 'text-gray-400 bg-gray-500/10 border-gray-500/20',
};

// ── Main Component ──

export default function AnalyzeReportPage() {
    const { token } = useAuthStore();
    const [view, setView] = useState<'list' | 'detail'>('list');
    const [analyses, setAnalyses] = useState<Analysis[]>([]);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [analysis, setAnalysis] = useState<Analysis | null>(null);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [ttps, setTTPs] = useState<TTP[]>([]);
    const [mindsetProfile, setMindsetProfile] = useState<MindsetProfile | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [uploading, setUploading] = useState(false);
    const [tab, setTab] = useState<'findings' | 'ttps' | 'mindset' | 'logs'>('findings');
    const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
    const [expandedTTP, setExpandedTTP] = useState<string | null>(null);
    const [useMindset, setUseMindset] = useState(() => {
        if (typeof window !== 'undefined') return localStorage.getItem('penpard_use_mindset') !== 'false';
        return true;
    });

    // no-store to bypass Next.js / browser cache on every fetch
    const authHeaders = useCallback(() => ({
        'Authorization': `Bearer ${token}`,
        'Cache-Control': 'no-store',
    }), [token]);

    // ── Fetch list ──
    const fetchAnalyses = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/report-analysis`, {
                headers: authHeaders(),
                cache: 'no-store',
            });
            if (res.ok) { const d = await res.json(); setAnalyses(d.analyses || []); }
        } catch { /* silent */ }
    }, [token]);

    // Refetch list on mount + window focus + visibility restore
    useEffect(() => {
        fetchAnalyses();
        const onFocus = () => fetchAnalyses();
        const onVisible = () => { if (document.visibilityState === 'visible') fetchAnalyses(); };
        window.addEventListener('focus', onFocus);
        document.addEventListener('visibilitychange', onVisible);
        return () => {
            window.removeEventListener('focus', onFocus);
            document.removeEventListener('visibilitychange', onVisible);
        };
    }, [fetchAnalyses]);

    // ── Fetch detail ──
    const fetchDetail = useCallback(async (id: string) => {
        try {
            const nocache: RequestInit = { headers: authHeaders(), cache: 'no-store' };
            const [aRes, fRes, lRes] = await Promise.all([
                fetch(`${API_URL}/report-analysis/${id}`, nocache),
                fetch(`${API_URL}/report-analysis/${id}/findings`, nocache),
                fetch(`${API_URL}/report-analysis/${id}/logs`, nocache),
            ]);
            if (aRes.ok) { const d = await aRes.json(); setAnalysis(d); }
            if (fRes.ok) { const d = await fRes.json(); setFindings(d.findings || []); }
            if (lRes.ok) { const d = await lRes.json(); setLogs(d.logs || []); }
        } catch { /* silent */ }
    }, [token]);

    // Fetch global TTPs and mindset profile (no-store)
    const fetchTTPs = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/report-analysis/ttps/list`, { headers: authHeaders(), cache: 'no-store' });
            if (res.ok) { const d = await res.json(); setTTPs(d.ttps || []); }
        } catch { /* silent */ }
    }, [token]);

    const fetchMindsetProfile = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/report-analysis/mindset-profile/current`, { headers: authHeaders(), cache: 'no-store' });
            if (res.ok) { const d = await res.json(); setMindsetProfile(d.profile || null); }
        } catch { /* silent */ }
    }, [token]);

    // Helper: is this a non-terminal status that needs polling?
    const TERMINAL = new Set(['completed', 'failed']);

    // Ref so the interval closure always reads the latest analysis status
    const analysisStatusRef = useRef<string | undefined>(undefined);
    useEffect(() => { analysisStatusRef.current = analysis?.status; }, [analysis?.status]);

    const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

    useEffect(() => {
        // Clear any previous interval
        if (pollIntervalRef.current) { clearInterval(pollIntervalRef.current); pollIntervalRef.current = null; }
        if (!selectedId) return;

        // Immediate fetch on mount / selectedId change
        fetchDetail(selectedId);
        fetchTTPs();
        fetchMindsetProfile();

        // Poll only while non-terminal
        pollIntervalRef.current = setInterval(() => {
            if (analysisStatusRef.current && TERMINAL.has(analysisStatusRef.current)) {
                // Stop polling once terminal — clear self
                if (pollIntervalRef.current) { clearInterval(pollIntervalRef.current); pollIntervalRef.current = null; }
                return;
            }
            fetchDetail(selectedId);
            fetchTTPs();
            fetchMindsetProfile();
        }, 2500);

        // Refetch on focus/visibility while in detail view
        const onFocus = () => fetchDetail(selectedId);
        const onVisible = () => { if (document.visibilityState === 'visible') fetchDetail(selectedId); };
        window.addEventListener('focus', onFocus);
        document.addEventListener('visibilitychange', onVisible);

        return () => {
            if (pollIntervalRef.current) { clearInterval(pollIntervalRef.current); pollIntervalRef.current = null; }
            window.removeEventListener('focus', onFocus);
            document.removeEventListener('visibilitychange', onVisible);
        };
    }, [selectedId]);

    // ── Upload ──
    const handleUpload = async (file: File) => {
        setUploading(true);
        try {
            const formData = new FormData();
            formData.append('report', file);
            const res = await fetch(`${API_URL}/report-analysis/upload`, {
                method: 'POST', headers: { 'Authorization': `Bearer ${token}` }, body: formData,
            });
            if (res.ok) {
                const data = await res.json();
                toast.success('Report uploaded! Learning pipeline started.');
                setSelectedId(data.analysisId);
                setView('detail');
                setTab('logs');
                fetchAnalyses();
            } else {
                const err = await res.json();
                toast.error(err.message || 'Upload failed');
            }
        } catch (error: any) {
            toast.error('Upload failed: ' + error.message);
        } finally {
            setUploading(false);
        }
    };

    const handleDelete = async (id: string) => {
        try {
            await fetch(`${API_URL}/report-analysis/${id}`, { method: 'DELETE', headers: authHeaders() });
            toast.success('Analysis deleted');
            fetchAnalyses();
            if (selectedId === id) { setView('list'); setSelectedId(null); }
        } catch { toast.error('Delete failed'); }
    };

    const handleExport = async (id: string) => {
        try {
            const res = await fetch(`${API_URL}/report-analysis/${id}/export`, { headers: authHeaders() });
            if (res.ok) {
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = `penpard-learning-${id}.json`; a.click();
                URL.revokeObjectURL(url);
                toast.success('Export downloaded');
            }
        } catch { toast.error('Export failed'); }
    };

    const toggleTTP = async (ttpId: string) => {
        try {
            await fetch(`${API_URL}/report-analysis/ttps/${ttpId}/toggle`, { method: 'PATCH', headers: authHeaders() });
            fetchTTPs();
        } catch { toast.error('Toggle failed'); }
    };

    const toggleUseMindset = () => {
        const next = !useMindset;
        setUseMindset(next);
        localStorage.setItem('penpard_use_mindset', String(next));
        toast.success(next ? 'Mindset Library: Enabled for scans' : 'Mindset Library: Disabled for scans');
    };

    const openAnalysis = (id: string) => {
        setSelectedId(id);
        setView('detail');
        setTab('findings');
    };

    const statusBadge = (status: string) => {
        const map: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
            pending: { icon: <Clock className="w-3 h-3" />, color: 'text-gray-400 bg-gray-500/10', label: 'Pending' },
            parsing: { icon: <Loader2 className="w-3 h-3 animate-spin" />, color: 'text-cyan-400 bg-cyan-500/10', label: 'Parsing' },
            analyzing: { icon: <Brain className="w-3 h-3 animate-pulse" />, color: 'text-purple-400 bg-purple-500/10', label: 'Learning' },
            completed: { icon: <CheckCircle className="w-3 h-3" />, color: 'text-green-400 bg-green-500/10', label: 'Completed' },
            failed: { icon: <AlertTriangle className="w-3 h-3" />, color: 'text-red-400 bg-red-500/10', label: 'Failed' },
        };
        const s = map[status] || map.pending;
        return <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${s.color}`}>{s.icon} {s.label}</span>;
    };

    // ══════════════════════════════
    // LIST VIEW
    // ══════════════════════════════

    if (view === 'list') {
        return (
            <div className="max-w-5xl mx-auto px-4 py-6">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-gradient-to-br from-purple-500/20 to-cyan-500/20 border border-purple-500/20">
                                <Brain className="w-6 h-6 text-purple-400" />
                            </div>
                            Report Learning Engine
                        </h1>
                        <p className="text-gray-500 mt-1 text-sm">Upload Red Team reports → Extract TTPs → Apply learned tactics to future scans</p>
                    </div>
                    <button
                        onClick={toggleUseMindset}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all border ${useMindset
                            ? 'bg-green-500/10 text-green-400 border-green-500/20 hover:bg-green-500/20'
                            : 'bg-gray-800/50 text-gray-500 border-gray-700/30 hover:bg-gray-700/30'
                            }`}
                    >
                        {useMindset ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                        Use in Scans
                    </button>
                </div>

                {/* Upload */}
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
                    <label className={`flex flex-col items-center justify-center w-full h-40 rounded-xl border-2 border-dashed transition-all cursor-pointer ${uploading ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-gray-700 hover:border-purple-500/50 hover:bg-purple-500/5'
                        }`}>
                        <input type="file" accept=".pdf,.docx" className="hidden" disabled={uploading}
                            onChange={(e) => { if (e.target.files?.[0]) handleUpload(e.target.files[0]); }} />
                        {uploading ? (
                            <div className="flex flex-col items-center gap-3">
                                <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                                <span className="text-cyan-400 text-sm font-medium">Processing...</span>
                            </div>
                        ) : (
                            <div className="flex flex-col items-center gap-3">
                                <Upload className="w-8 h-8 text-gray-500" />
                                <span className="text-gray-400 text-sm">Drop a <span className="text-purple-400 font-medium">PDF</span> or <span className="text-purple-400 font-medium">DOCX</span> pentest report</span>
                                <p className="text-gray-600 text-xs">Max 50MB</p>
                            </div>
                        )}
                    </label>
                </motion.div>

                {/* List */}
                <div className="space-y-3">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Analyzed Reports</h2>
                    {analyses.length === 0 ? (
                        <div className="text-center py-12 text-gray-600">
                            <FileSearch className="w-12 h-12 mx-auto mb-3 opacity-40" />
                            <p>No reports yet. Upload one to start learning.</p>
                        </div>
                    ) : analyses.map((a) => (
                        <motion.div key={a.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                            className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-4 hover:border-purple-500/20 transition-all cursor-pointer group"
                            onClick={() => openAnalysis(a.id)}>
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-purple-500/10"><FileSearch className="w-4 h-4 text-purple-400" /></div>
                                    <div>
                                        <h3 className="text-white font-medium text-sm group-hover:text-purple-300 transition-colors">{a.filename}</h3>
                                        <p className="text-gray-600 text-xs">{new Date(a.created_at).toLocaleString()}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    {statusBadge(a.status)}
                                    <button onClick={(e) => { e.stopPropagation(); handleDelete(a.id); }}
                                        className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition-all opacity-0 group-hover:opacity-100">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    ))}
                </div>
            </div>
        );
    }

    // ══════════════════════════════
    // DETAIL VIEW
    // ══════════════════════════════

    return (
        <div className="max-w-6xl mx-auto px-4 py-6">
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <button onClick={() => { setView('list'); setSelectedId(null); }} className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all">
                        <ArrowLeft className="w-5 h-5" />
                    </button>
                    <div>
                        <h1 className="text-lg font-bold text-white">{analysis?.filename || 'Loading...'}</h1>
                        <div className="flex items-center gap-3 mt-0.5">
                            {analysis && statusBadge(analysis.status)}
                            {analysis?.completed_at && <span className="text-gray-600 text-xs">Completed: {new Date(analysis.completed_at).toLocaleString()}</span>}
                        </div>
                    </div>
                </div>
                {analysis?.status === 'completed' && (
                    <button onClick={() => handleExport(analysis.id)} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 text-sm font-medium hover:bg-cyan-500/20 transition-all border border-cyan-500/20">
                        <Download className="w-4 h-4" /> Export
                    </button>
                )}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 mb-6 bg-dark-900/50 p-1 rounded-xl border border-white/[0.06]">
                {[
                    { key: 'findings', icon: Target, label: 'Findings', badge: findings.length },
                    { key: 'ttps', icon: BookOpen, label: 'Learned TTPs', badge: ttps.length },
                    { key: 'mindset', icon: Brain, label: 'Mindset Profile' },
                    { key: 'logs', icon: Activity, label: 'Logs' },
                ].map(({ key, icon: Icon, label, badge }) => (
                    <button key={key} onClick={() => setTab(key as any)}
                        className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-all ${tab === key ? 'bg-purple-500/20 text-purple-300 border border-purple-500/20' : 'text-gray-500 hover:text-gray-300'
                            }`}>
                        <Icon className="w-4 h-4" /> {label}
                        {badge !== undefined && badge > 0 && <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-purple-500/20 text-purple-400">{badge}</span>}
                    </button>
                ))}
            </div>

            <AnimatePresence mode="wait">
                {/* ── FINDINGS ── */}
                {tab === 'findings' && (
                    <motion.div key="findings" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
                        {findings.length === 0 ? (
                            <div className="text-center py-16 text-gray-600">{analysis?.status === 'completed' ? 'No findings extracted.' : 'Waiting for extraction...'}</div>
                        ) : findings.map((f) => (
                            <div key={f.id} className="bg-dark-900/50 border border-white/[0.06] rounded-xl overflow-hidden">
                                <button onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                                    className="w-full flex items-center justify-between p-4 hover:bg-white/[0.02] transition-all">
                                    <div className="flex items-center gap-3">
                                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${severityColor[f.severity?.toLowerCase()] || severityColor.info}`}>{f.severity}</span>
                                        <span className="text-white font-medium text-sm">{f.title}</span>
                                        {f.cvss_score && <span className="text-gray-500 text-xs">CVSS {f.cvss_score}</span>}
                                    </div>
                                    {expandedFinding === f.id ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                                </button>
                                <AnimatePresence>
                                    {expandedFinding === f.id && (
                                        <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                                            <div className="px-4 pb-4 space-y-4 border-t border-white/[0.04] pt-4">
                                                <div><h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Description</h4><p className="text-gray-300 text-sm">{f.description}</p></div>
                                                {f.poc_steps.length > 0 && <div><h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">PoC Steps</h4><ol className="list-decimal list-inside space-y-1">{f.poc_steps.map((s, i) => <li key={i} className="text-gray-300 text-sm">{s}</li>)}</ol></div>}
                                                {f.payloads.length > 0 && <div><h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Payloads</h4>{f.payloads.map((p, i) => <code key={i} className="block text-xs text-cyan-300 bg-black/50 px-2 py-1 rounded font-mono mb-1">{p}</code>)}</div>}
                                                {f.recommendation && <div><h4 className="text-xs font-semibold text-gray-500 uppercase mb-1">Recommendation</h4><p className="text-gray-300 text-sm">{f.recommendation}</p></div>}
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        ))}
                    </motion.div>
                )}

                {/* ── LEARNED TTPs ── */}
                {tab === 'ttps' && (
                    <motion.div key="ttps" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
                        {ttps.length === 0 ? (
                            <div className="text-center py-16 text-gray-600">{analysis?.status === 'completed' ? 'No TTPs derived.' : <><Loader2 className="w-6 h-6 mx-auto mb-2 animate-spin" /> Deriving TTPs...</>}</div>
                        ) : ttps.map((ttp) => (
                            <div key={ttp.id} className={`bg-dark-900/50 border rounded-xl overflow-hidden transition-all ${ttp.is_active ? 'border-white/[0.06]' : 'border-white/[0.03] opacity-60'}`}>
                                <div
                                    role="button"
                                    tabIndex={0}
                                    aria-expanded={expandedTTP === ttp.id}
                                    onClick={() => setExpandedTTP(expandedTTP === ttp.id ? null : ttp.id)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' || e.key === ' ') {
                                            e.preventDefault();
                                            setExpandedTTP(expandedTTP === ttp.id ? null : ttp.id);
                                        }
                                    }}
                                    className="w-full flex items-center justify-between p-4 hover:bg-white/[0.02] transition-all cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500/50 focus-visible:ring-inset rounded-t-xl"
                                >
                                    <div className="flex items-center gap-3">
                                        <span className="px-2 py-0.5 rounded text-xs font-bold uppercase bg-purple-500/10 text-purple-400 border border-purple-500/20">{ttp.vulnerability_class}</span>
                                        <span className="text-white font-medium text-sm">{ttp.title}</span>
                                        <span className="text-gray-500 text-xs">{Math.round(ttp.confidence * 100)}%</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <button
                                            onClick={(e) => { e.stopPropagation(); toggleTTP(ttp.id); }}
                                            aria-pressed={!!ttp.is_active}
                                            aria-label={ttp.is_active ? 'Deactivate TTP' : 'Activate TTP'}
                                            className={`p-1 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500/50 ${ttp.is_active ? 'text-green-400' : 'text-gray-600'}`}
                                        >
                                            {ttp.is_active ? <ToggleRight className="w-5 h-5" /> : <ToggleLeft className="w-5 h-5" />}
                                        </button>
                                        {expandedTTP === ttp.id ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                                    </div>
                                </div>
                                <AnimatePresence>
                                    {expandedTTP === ttp.id && (
                                        <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                                            <div className="px-4 pb-4 space-y-4 border-t border-white/[0.04] pt-4">
                                                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                                    <div className="bg-black/30 rounded-lg p-3">
                                                        <p className="text-gray-500 text-[10px] uppercase font-semibold mb-1">Discovery Strategy</p>
                                                        <div className="flex flex-wrap gap-1">{ttp.discovery_strategy.map((s, i) => <span key={i} className="px-1.5 py-0.5 rounded text-[11px] bg-purple-500/10 text-purple-300">{s}</span>)}</div>
                                                    </div>
                                                    <div className="bg-black/30 rounded-lg p-3">
                                                        <p className="text-gray-500 text-[10px] uppercase font-semibold mb-1">Entrypoints</p>
                                                        <p className="text-cyan-300 text-xs font-mono">{(ttp.entrypoint_hints.endpoints || []).join(', ') || 'Generic'}</p>
                                                        <p className="text-gray-400 text-xs mt-0.5">Params: {(ttp.entrypoint_hints.params || []).join(', ') || 'Any'}</p>
                                                    </div>
                                                    <div className="bg-black/30 rounded-lg p-3">
                                                        <p className="text-gray-500 text-[10px] uppercase font-semibold mb-1">Confidence</p>
                                                        <div className="flex items-center gap-2">
                                                            <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                                                <div className="h-full bg-purple-400 rounded-full" style={{ width: `${ttp.confidence * 100}%` }} />
                                                            </div>
                                                            <span className="text-purple-400 text-xs font-mono">{Math.round(ttp.confidence * 100)}%</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                {ttp.verification_criteria.length > 0 && (
                                                    <div><p className="text-gray-500 text-[10px] uppercase font-semibold mb-1">Verification Criteria</p>
                                                        <ul className="space-y-1">{ttp.verification_criteria.map((c, i) => <li key={i} className="text-gray-300 text-xs flex items-start gap-1.5"><span className="text-green-500 mt-0.5">✓</span>{c}</li>)}</ul>
                                                    </div>
                                                )}
                                                {ttp.generalization_notes && <div><p className="text-gray-500 text-[10px] uppercase font-semibold mb-1">Generalization</p><p className="text-gray-300 text-sm">{ttp.generalization_notes}</p></div>}
                                                {ttp.request_templates.length > 0 && (
                                                    <div><p className="text-gray-500 text-[10px] uppercase font-semibold mb-1">Request Templates</p>
                                                        {ttp.request_templates.map((rt, i) => <code key={i} className="block text-xs text-cyan-300 bg-black/50 px-2 py-1 rounded font-mono mb-1">{rt.method} {rt.path}</code>)}
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        ))}
                    </motion.div>
                )}

                {/* ── MINDSET PROFILE ── */}
                {tab === 'mindset' && (
                    <motion.div key="mindset" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                        {mindsetProfile ? (
                            <div className="space-y-6">
                                {/* Stats */}
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-4 text-center">
                                        <BookOpen className="w-6 h-6 mx-auto text-purple-400 mb-2" />
                                        <p className="text-2xl font-bold text-white">{mindsetProfile.total_ttps}</p>
                                        <p className="text-gray-500 text-xs">Total TTPs</p>
                                    </div>
                                    <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-4 text-center">
                                        <Zap className="w-6 h-6 mx-auto text-yellow-400 mb-2" />
                                        <p className="text-2xl font-bold text-white">{mindsetProfile.sophistication_score}<span className="text-gray-500 text-sm">/10</span></p>
                                        <p className="text-gray-500 text-xs">Sophistication</p>
                                    </div>
                                    <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-4 text-center">
                                        <Target className="w-6 h-6 mx-auto text-cyan-400 mb-2" />
                                        <p className="text-2xl font-bold text-white">{mindsetProfile.common_vuln_classes.length}</p>
                                        <p className="text-gray-500 text-xs">Vuln Classes</p>
                                    </div>
                                    <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-4 text-center">
                                        <BarChart3 className="w-6 h-6 mx-auto text-green-400 mb-2" />
                                        <p className="text-2xl font-bold text-white">{mindsetProfile.common_strategies.length}</p>
                                        <p className="text-gray-500 text-xs">Strategies</p>
                                    </div>
                                </div>

                                {/* Vuln Classes Bar */}
                                {mindsetProfile.common_vuln_classes.length > 0 && (
                                    <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-5">
                                        <h3 className="text-white font-medium text-sm mb-4 flex items-center gap-2"><Target className="w-4 h-4 text-purple-400" /> Vulnerability Classes</h3>
                                        <div className="space-y-2">
                                            {mindsetProfile.common_vuln_classes.map(({ class: cls, count }) => {
                                                const maxCount = mindsetProfile.common_vuln_classes[0]?.count || 1;
                                                return (
                                                    <div key={cls} className="flex items-center gap-3">
                                                        <span className="text-gray-300 text-sm w-40 truncate">{cls}</span>
                                                        <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                                                            <div className="h-full bg-gradient-to-r from-purple-500 to-cyan-500 rounded-full transition-all" style={{ width: `${(count / maxCount) * 100}%` }} />
                                                        </div>
                                                        <span className="text-gray-500 text-xs w-6 text-right">{count}</span>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {/* Strategies + Sequences */}
                                <div className="grid md:grid-cols-2 gap-4">
                                    {mindsetProfile.common_strategies.length > 0 && (
                                        <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-5">
                                            <h3 className="text-white font-medium text-sm mb-3">Common Strategies</h3>
                                            <div className="flex flex-wrap gap-2">
                                                {mindsetProfile.common_strategies.map((s) => <span key={s} className="px-2 py-1 rounded-full text-xs bg-purple-500/10 text-purple-300 border border-purple-500/20">{s}</span>)}
                                            </div>
                                        </div>
                                    )}
                                    {mindsetProfile.preferred_sequences.length > 0 && (
                                        <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-5">
                                            <h3 className="text-white font-medium text-sm mb-3">Preferred Sequences</h3>
                                            <div className="space-y-2">
                                                {mindsetProfile.preferred_sequences.map((seq, i) => <p key={i} className="text-cyan-300 text-xs font-mono bg-black/30 px-2 py-1.5 rounded">{seq}</p>)}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        ) : (
                            <div className="text-center py-16 text-gray-600">
                                {analysis?.status === 'completed' ? 'No mindset profile available.' : <><Loader2 className="w-6 h-6 mx-auto mb-2 animate-spin" /> Building mindset profile...</>}
                            </div>
                        )}
                    </motion.div>
                )}

                {/* ── LOGS ── */}
                {tab === 'logs' && (
                    <motion.div key="logs" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                        <div className="bg-black/60 rounded-xl border border-white/[0.06] p-4 max-h-[600px] overflow-y-auto font-mono text-xs space-y-1">
                            {logs.length === 0 ? (
                                <div className="text-gray-600 text-center py-8">
                                    {analysis?.status === 'pending' ? 'Waiting to start...' : <><Loader2 className="w-4 h-4 mx-auto mb-2 animate-spin" /> Processing...</>}
                                </div>
                            ) : logs.map((log, i) => <div key={i} className="text-gray-400 hover:text-gray-200 transition-colors py-0.5">{log}</div>)}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
