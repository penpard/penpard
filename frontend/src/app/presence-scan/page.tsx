'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Crosshair, BookOpen, Plus, ArrowLeft, Loader2, CheckCircle,
    AlertTriangle, Clock, Square, Trash2, Download, Search, Filter,
    Eye, X, Target, Upload, ChevronDown, ChevronRight,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import toast from 'react-hot-toast';

// ── Types ──

interface RunTTP { ttp_id: string; ttp_title: string | null }

interface ScanRun {
    id: string;
    ttp_id: string;
    ttp_title: string;
    ttps: RunTTP[];
    status: string;
    targets_count: number;
    results_present: number;
    results_likely: number;
    results_absent: number;
    results_unknown: number;
    created_at: string;
    started_at: string;
    finished_at: string;
    error_message?: string;
}

interface TargetResult {
    id: number;
    target_url: string;
    target_raw: string;
    verdict: string;
    verdict_reason: string;
    evidence: any;  // per_ttp breakdown or flat array
    request_sent: string;
    response_excerpt: string;
    checked_at: string;
}

interface TTP {
    id: string;
    title: string;
    vulnerability_class: string;
    confidence: number;
    is_active: number;
}

// ── Verdict helpers ──

const VERDICT_CONFIG: Record<string, { label: string; color: string; bg: string; border: string }> = {
    present: { label: 'Present', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20' },
    likely: { label: 'Likely', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
    absent: { label: 'Absent', color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20' },
    unknown: { label: 'Unknown', color: 'text-red-400', bg: 'bg-red-500/15', border: 'border-red-500/20' },
};

function VerdictBadge({ verdict }: { verdict: string }) {
    const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.unknown;
    return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${cfg.color} ${cfg.bg} border ${cfg.border}`}>
            {cfg.label}
        </span>
    );
}

const STATUS_MAP: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
    pending: { icon: <Clock className="w-3 h-3" />, color: 'text-gray-400 bg-gray-500/10', label: 'Pending' },
    running: { icon: <Loader2 className="w-3 h-3 animate-spin" />, color: 'text-cyan-400 bg-cyan-500/10', label: 'Running' },
    completed: { icon: <CheckCircle className="w-3 h-3" />, color: 'text-green-400 bg-green-500/10', label: 'Completed' },
    stopped: { icon: <Square className="w-3 h-3" />, color: 'text-yellow-400 bg-yellow-500/10', label: 'Stopped' },
    failed: { icon: <AlertTriangle className="w-3 h-3" />, color: 'text-red-400 bg-red-500/10', label: 'Failed' },
};

function StatusBadge({ status }: { status: string }) {
    const s = STATUS_MAP[status] || STATUS_MAP.pending;
    return <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${s.color}`}>{s.icon} {s.label}</span>;
}

// ── Multi-TTP selector component ──

function TTPMultiSelect({
    ttps, selected, onChange,
}: { ttps: TTP[]; selected: string[]; onChange: (ids: string[]) => void }) {
    const [search, setSearch] = useState('');

    const filtered = ttps.filter(t =>
        t.title.toLowerCase().includes(search.toLowerCase()) ||
        t.vulnerability_class.toLowerCase().includes(search.toLowerCase())
    );

    const toggle = (id: string) => {
        if (selected.includes(id)) onChange(selected.filter(s => s !== id));
        else onChange([...selected, id]);
    };

    return (
        <div className="bg-dark-900/80 border border-white/[0.08] rounded-xl overflow-hidden">
            {/* Search */}
            <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.05]">
                <Search className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                <input
                    type="text"
                    placeholder="Search TTPs..."
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="flex-1 bg-transparent text-white text-sm outline-none placeholder:text-gray-600"
                />
                <div className="flex items-center gap-2 text-xs">
                    <button onClick={() => onChange(ttps.map(t => t.id))} className="text-cyan-400 hover:text-cyan-300">All</button>
                    <span className="text-gray-700">·</span>
                    <button onClick={() => onChange([])} className="text-gray-500 hover:text-gray-300">Clear</button>
                </div>
            </div>

            {/* List */}
            <div className="max-h-56 overflow-y-auto divide-y divide-white/[0.03]">
                {filtered.length === 0 ? (
                    <p className="text-center text-gray-600 text-sm py-6">No TTPs match</p>
                ) : filtered.map(ttp => {
                    const isSelected = selected.includes(ttp.id);
                    return (
                        <div
                            key={ttp.id}
                            role="button"
                            tabIndex={0}
                            onClick={() => toggle(ttp.id)}
                            onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(ttp.id); } }}
                            className={`flex items-center gap-3 px-3 py-2.5 cursor-pointer transition-all focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/50 ${isSelected ? 'bg-cyan-500/10' : 'hover:bg-white/[0.03]'}`}
                        >
                            <div className={`w-4 h-4 rounded border shrink-0 flex items-center justify-center transition-all ${isSelected ? 'bg-cyan-500 border-cyan-500' : 'border-gray-600'}`}>
                                {isSelected && <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>}
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className={`text-sm font-medium truncate ${isSelected ? 'text-cyan-300' : 'text-gray-300'}`}>{ttp.title}</p>
                                <p className="text-xs text-gray-600 truncate">{ttp.vulnerability_class} · {Math.round(ttp.confidence * 100)}%</p>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Footer */}
            {selected.length > 0 && (
                <div className="px-3 py-2 border-t border-white/[0.05] text-xs text-cyan-400">
                    {selected.length} TTP{selected.length > 1 ? 's' : ''} selected
                </div>
            )}
        </div>
    );
}

// ── Main Component ──

export default function PresenceScanPage() {
    const { token } = useAuthStore();
    const [view, setView] = useState<'list' | 'create' | 'detail'>('list');
    const [runs, setRuns] = useState<ScanRun[]>([]);
    const [selectedRun, setSelectedRun] = useState<ScanRun | null>(null);
    const [results, setResults] = useState<TargetResult[]>([]);
    const [logs, setLogs] = useState<string[]>([]);
    const [ttps, setTTPs] = useState<TTP[]>([]);
    const [verdictFilter, setVerdictFilter] = useState<string>('');
    const [searchQuery, setSearchQuery] = useState('');
    const [drawerTarget, setDrawerTarget] = useState<TargetResult | null>(null);
    const [creating, setCreating] = useState(false);
    const [form, setForm] = useState<{ ttp_ids: string[]; targets_raw: string; targets_format: string }>({
        ttp_ids: [], targets_raw: '', targets_format: 'auto',
    });
    const [fileUploading, setFileUploading] = useState(false);
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const runStatusRef = useRef<string | undefined>(undefined);

    const authHeaders = useCallback(() => ({
        'Authorization': `Bearer ${token}`,
        'Cache-Control': 'no-store',
    }), [token]);

    // ── Fetch ──

    const fetchRuns = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/presence-scan/runs`, { headers: authHeaders(), cache: 'no-store' });
            if (res.ok) { const d = await res.json(); setRuns(d.runs || []); }
        } catch { /* silent */ }
    }, [token]);

    const fetchTTPs = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/report-analysis/ttps/list`, { headers: authHeaders(), cache: 'no-store' });
            if (res.ok) { const d = await res.json(); setTTPs((d.ttps || []).filter((t: TTP) => t.is_active)); }
        } catch { /* silent */ }
    }, [token]);

    const fetchDetail = useCallback(async (id: string) => {
        try {
            const h = { headers: authHeaders(), cache: 'no-store' as RequestCache };
            const [runRes, resRes, logRes] = await Promise.all([
                fetch(`${API_URL}/presence-scan/runs/${id}`, h),
                fetch(`${API_URL}/presence-scan/runs/${id}/results?per_page=200`, h),
                fetch(`${API_URL}/presence-scan/runs/${id}/logs`, h),
            ]);
            if (runRes.ok) { const d = await runRes.json(); setSelectedRun(d); runStatusRef.current = d.status; }
            if (resRes.ok) { const d = await resRes.json(); setResults(d.results || []); }
            if (logRes.ok) { const d = await logRes.json(); setLogs(d.logs || []); }
        } catch { /* silent */ }
    }, [token]);

    useEffect(() => {
        fetchRuns();
        fetchTTPs();
        const onFocus = () => fetchRuns();
        window.addEventListener('focus', onFocus);
        return () => window.removeEventListener('focus', onFocus);
    }, [fetchRuns, fetchTTPs]);

    // Poll detail
    useEffect(() => {
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
        if (view !== 'detail' || !selectedRun) return;

        const TERMINAL = new Set(['completed', 'failed', 'stopped']);
        pollRef.current = setInterval(() => {
            if (runStatusRef.current && TERMINAL.has(runStatusRef.current)) {
                if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
                return;
            }
            fetchDetail(selectedRun.id);
        }, 2500);

        return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
    }, [view, selectedRun?.id]);

    // ── File upload → read as text ──

    const handleFileUpload = async (file: File) => {
        setFileUploading(true);
        try {
            const text = await file.text();
            // Auto-detect format from extension
            const ext = file.name.split('.').pop()?.toLowerCase();
            const fmt = ext === 'json' ? 'json' : ext === 'csv' ? 'csv' : 'txt';
            setForm(f => ({ ...f, targets_raw: text, targets_format: fmt }));
            toast.success(`Loaded ${file.name} — ${text.split('\n').filter(l => l.trim()).length} lines`);
        } catch { toast.error('Failed to read file'); }
        finally { setFileUploading(false); }
    };

    // ── Actions ──

    const createRun = async () => {
        if (form.ttp_ids.length === 0) return toast.error('Select at least one TTP');
        if (!form.targets_raw.trim()) return toast.error('Enter or upload a target list');
        setCreating(true);
        try {
            const res = await fetch(`${API_URL}/presence-scan/runs`, {
                method: 'POST',
                headers: { ...authHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            });
            const data = await res.json();
            if (res.ok) {
                toast.success(`Scan started — ${data.targets_count} targets × ${data.ttp_count} TTPs`);
                setView('list');
                fetchRuns();
                setTimeout(() => openRun(data.runId), 800);
            } else {
                toast.error(data.message || 'Failed to start scan');
            }
        } catch { toast.error('Request failed'); }
        finally { setCreating(false); }
    };

    const stopRun = async (id: string) => {
        try {
            await fetch(`${API_URL}/presence-scan/runs/${id}/stop`, { method: 'POST', headers: authHeaders() });
            toast.success('Stop signal sent');
            fetchDetail(id);
        } catch { toast.error('Failed to stop'); }
    };

    const deleteRun = async (id: string) => {
        try {
            await fetch(`${API_URL}/presence-scan/runs/${id}`, { method: 'DELETE', headers: authHeaders() });
            toast.success('Run deleted');
            setView('list');
            fetchRuns();
        } catch { toast.error('Delete failed'); }
    };

    const exportResults = async (run: ScanRun) => {
        try {
            const res = await fetch(`${API_URL}/presence-scan/runs/${run.id}/results?per_page=10000`, { headers: authHeaders() });
            const data = await res.json();
            const blob = new Blob([JSON.stringify({ run, results: data.results }, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = `presence-scan-${run.id}.json`; a.click();
            URL.revokeObjectURL(url);
        } catch { toast.error('Export failed'); }
    };

    const openRun = (id: string) => {
        setResults([]); setLogs([]); setVerdictFilter(''); setSearchQuery('');
        runStatusRef.current = undefined;
        setSelectedRun(null);
        setView('detail');
        fetchDetail(id);
    };

    // ── Filtered results ──

    const filteredResults = results.filter(r => {
        if (verdictFilter && r.verdict !== verdictFilter) return false;
        if (searchQuery && !r.target_url.toLowerCase().includes(searchQuery.toLowerCase())) return false;
        return true;
    });

    // ══════════════════════════════
    // LIST VIEW
    // ══════════════════════════════

    if (view === 'list') {
        return (
            <div className="max-w-5xl mx-auto px-4 py-6">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/20">
                                <Crosshair className="w-6 h-6 text-cyan-400" />
                            </div>
                            Presence Scan
                        </h1>
                        <p className="text-gray-500 mt-1 text-sm">Select learned TTPs + target list → hypothesis-driven presence check per target</p>
                    </div>
                    <button
                        onClick={() => { setForm({ ttp_ids: [], targets_raw: '', targets_format: 'auto' }); setView('create'); }}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 text-cyan-400 font-medium text-sm hover:bg-cyan-500/20 transition-all border border-cyan-500/20"
                    >
                        <Plus className="w-4 h-4" /> New Scan
                    </button>
                </div>

                {runs.length === 0 ? (
                    <div className="text-center py-20 text-gray-600">
                        <Crosshair className="w-12 h-12 mx-auto mb-4 opacity-30" />
                        <p className="font-medium">No presence scans yet.</p>
                        <p className="text-sm mt-1">Upload a Red Team report first to learn TTPs, then create a scan.</p>
                    </div>
                ) : (
                    <div className="space-y-3">
                        {runs.map(run => {
                            const ttpList = run.ttps?.length > 0 ? run.ttps : [{ ttp_id: run.ttp_id, ttp_title: run.ttp_title }];
                            return (
                                <motion.div key={run.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                                    className="bg-dark-900/50 border border-white/[0.06] rounded-xl p-4 hover:border-cyan-500/20 transition-all cursor-pointer group"
                                    onClick={() => openRun(run.id)}>
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className="p-2 rounded-lg bg-cyan-500/10"><Target className="w-4 h-4 text-cyan-400" /></div>
                                            <div>
                                                <div className="flex items-center gap-2 flex-wrap">
                                                    {ttpList.slice(0, 2).map(t => (
                                                        <span key={t.ttp_id} className="text-white font-medium text-sm group-hover:text-cyan-300 transition-colors">{t.ttp_title || t.ttp_id}</span>
                                                    ))}
                                                    {ttpList.length > 2 && <span className="text-xs text-gray-500">+{ttpList.length - 2} more</span>}
                                                    <StatusBadge status={run.status} />
                                                </div>
                                                <p className="text-gray-600 text-xs mt-0.5">{run.targets_count} targets · {new Date(run.created_at).toLocaleString()}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            {!['pending', 'running'].includes(run.status) && (
                                                <div className="flex items-center gap-3 text-xs font-medium">
                                                    <span className="text-green-400">{run.results_present}P</span>
                                                    <span className="text-yellow-400">{run.results_likely}L</span>
                                                    <span className="text-gray-500">{run.results_absent}A</span>
                                                    <span className="text-red-400">{run.results_unknown}U</span>
                                                </div>
                                            )}
                                            <button onClick={e => { e.stopPropagation(); deleteRun(run.id); }}
                                                className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition-all opacity-0 group-hover:opacity-100">
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                    </div>
                                </motion.div>
                            );
                        })}
                    </div>
                )}
            </div>
        );
    }

    // ══════════════════════════════
    // CREATE VIEW
    // ══════════════════════════════

    if (view === 'create') {
        return (
            <div className="max-w-3xl mx-auto px-4 py-6">
                <div className="flex items-center gap-3 mb-8">
                    <button onClick={() => setView('list')} className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all">
                        <ArrowLeft className="w-5 h-5" />
                    </button>
                    <h1 className="text-xl font-bold text-white">New Presence Scan</h1>
                </div>

                <div className="space-y-6">
                    {/* TTP Multi-select */}
                    <div>
                        <label className="flex items-center gap-1.5 text-sm font-medium text-gray-300 mb-2">
                            <BookOpen className="w-4 h-4 text-purple-400" />
                            Learned TTPs
                        </label>
                        {ttps.length === 0 ? (
                            <div className="text-sm text-gray-600 bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4">
                                No active TTPs available. Upload a Red Team report first.
                            </div>
                        ) : (
                            <TTPMultiSelect ttps={ttps} selected={form.ttp_ids} onChange={ids => setForm(f => ({ ...f, ttp_ids: ids }))} />
                        )}
                    </div>

                    {/* Target input */}
                    <div>
                        <div className="flex items-center justify-between mb-2">
                            <label className="flex items-center gap-1.5 text-sm font-medium text-gray-300">
                                <Target className="w-4 h-4 text-cyan-400" />
                                Target List
                            </label>
                            {/* Format pills */}
                            <div className="flex gap-1.5">
                                {['auto', 'txt', 'csv', 'json'].map(fmt => (
                                    <button key={fmt} onClick={() => setForm(f => ({ ...f, targets_format: fmt }))}
                                        className={`px-2 py-0.5 rounded text-[10px] font-medium transition-all border ${form.targets_format === fmt ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30' : 'text-gray-600 border-white/[0.05] hover:text-gray-300'}`}>
                                        {fmt.toUpperCase()}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* File upload drop zone */}
                        <label className="flex items-center gap-3 w-full mb-2 px-4 py-2.5 rounded-xl bg-dark-900/60 border border-dashed border-white/[0.08] cursor-pointer hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all">
                            <input
                                type="file"
                                accept=".txt,.csv,.json"
                                className="hidden"
                                onChange={e => { if (e.target.files?.[0]) handleFileUpload(e.target.files[0]); }}
                            />
                            {fileUploading
                                ? <><Loader2 className="w-4 h-4 text-cyan-400 animate-spin" /><span className="text-cyan-400 text-sm">Reading file...</span></>
                                : <><Upload className="w-4 h-4 text-gray-500" /><span className="text-gray-500 text-sm">Upload .txt / .csv / .json  <span className="text-gray-700">or paste below</span></span></>
                            }
                        </label>

                        <textarea
                            value={form.targets_raw}
                            onChange={e => setForm(f => ({ ...f, targets_raw: e.target.value }))}
                            rows={8}
                            placeholder={`One per line:\nexample.com\nhttps://api.example.com\nbeta.example.org:8443\n\nJSON: ["a.com","https://b.com"]\nCSV: fqdn,url  →  example.com,https`}
                            className="w-full bg-dark-900/80 border border-white/[0.08] rounded-xl px-3 py-2.5 text-white text-sm font-mono focus:outline-none focus:border-cyan-500/40 resize-y"
                        />
                        {form.targets_raw.trim() && (
                            <p className="text-xs text-gray-600 mt-1">
                                ~{form.targets_raw.trim().split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#')).length} lines detected
                            </p>
                        )}
                    </div>

                    <button
                        onClick={createRun}
                        disabled={creating || form.ttp_ids.length === 0 || !form.targets_raw.trim()}
                        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-cyan-500/20 text-cyan-300 font-semibold hover:bg-cyan-500/30 transition-all border border-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        {creating
                            ? <><Loader2 className="w-4 h-4 animate-spin" /> Starting...</>
                            : <><Crosshair className="w-4 h-4" /> Start Presence Scan {form.ttp_ids.length > 0 && `(${form.ttp_ids.length} TTP${form.ttp_ids.length > 1 ? 's' : ''})`}</>}
                    </button>
                </div>
            </div>
        );
    }

    // ══════════════════════════════
    // DETAIL VIEW
    // ══════════════════════════════

    const run = selectedRun;
    if (!run) return <div className="text-center py-20 text-gray-600"><Loader2 className="w-6 h-6 mx-auto animate-spin" /></div>;

    const checked = run.results_present + run.results_likely + run.results_absent + run.results_unknown;
    const progress = run.targets_count > 0 ? Math.round((checked / run.targets_count) * 100) : 0;
    const runTTPs = run.ttps?.length > 0 ? run.ttps : [{ ttp_id: run.ttp_id, ttp_title: run.ttp_title }];

    return (
        <div className="max-w-6xl mx-auto px-4 py-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <button onClick={() => { setView('list'); fetchRuns(); }} className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all">
                        <ArrowLeft className="w-5 h-5" />
                    </button>
                    <div>
                        <div className="flex flex-wrap items-center gap-2">
                            {runTTPs.map(t => (
                                <span key={t.ttp_id} className="text-white font-bold text-base">{t.ttp_title}</span>
                            ))}
                            {runTTPs.length > 1 && <span className="text-gray-600 text-sm">({runTTPs.length} TTPs)</span>}
                        </div>
                        <div className="flex items-center gap-3 mt-0.5">
                            <StatusBadge status={run.status} />
                            <span className="text-gray-600 text-xs">{run.targets_count} targets</span>
                            {run.finished_at && <span className="text-gray-600 text-xs">· {new Date(run.finished_at).toLocaleString()}</span>}
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    {run.status === 'running' && (
                        <button onClick={() => stopRun(run.id)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-yellow-500/10 text-yellow-400 text-sm font-medium hover:bg-yellow-500/20 transition-all border border-yellow-500/20">
                            <Square className="w-4 h-4" /> Stop
                        </button>
                    )}
                    {['completed', 'stopped'].includes(run.status) && (
                        <button onClick={() => exportResults(run)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 text-sm font-medium hover:bg-cyan-500/20 transition-all border border-cyan-500/20">
                            <Download className="w-4 h-4" /> Export JSON
                        </button>
                    )}
                    <button onClick={() => deleteRun(run.id)} className="p-2 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition-all">
                        <Trash2 className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* Progress bar */}
            {run.status === 'running' && (
                <div className="mb-5 bg-dark-900/50 border border-white/[0.06] rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2 text-xs text-gray-400">
                        <span>Checking targets ({checked}/{run.targets_count})</span><span>{progress}%</span>
                    </div>
                    <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 rounded-full transition-all" style={{ width: `${progress}%` }} />
                    </div>
                </div>
            )}

            {/* Verdict summary (clickable filters) */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                {[
                    { key: 'present', label: 'Present', count: run.results_present, color: 'text-green-400', bg: 'bg-green-500/10' },
                    { key: 'likely', label: 'Likely', count: run.results_likely, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
                    { key: 'absent', label: 'Absent', count: run.results_absent, color: 'text-gray-400', bg: 'bg-gray-500/10' },
                    { key: 'unknown', label: 'Unknown', count: run.results_unknown, color: 'text-red-400', bg: 'bg-red-500/10' },
                ].map(({ key, label, count, color, bg }) => (
                    <button key={key}
                        onClick={() => setVerdictFilter(verdictFilter === key ? '' : key)}
                        className={`${bg} rounded-xl p-4 text-center transition-all border ${verdictFilter === key ? 'border-white/20 ring-1 ring-white/10' : 'border-white/[0.04] hover:border-white/10'}`}>
                        <p className={`text-2xl font-bold ${color}`}>{count}</p>
                        <p className="text-xs text-gray-500 mt-0.5">{label}</p>
                    </button>
                ))}
            </div>

            {/* Results table */}
            <div className="bg-dark-900/50 border border-white/[0.06] rounded-xl overflow-hidden">
                <div className="flex items-center gap-3 p-3 border-b border-white/[0.04]">
                    <div className="flex-1 flex items-center gap-2 bg-black/30 rounded-lg px-3 py-1.5">
                        <Search className="w-3.5 h-3.5 text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search targets..."
                            value={searchQuery}
                            onChange={e => setSearchQuery(e.target.value)}
                            className="flex-1 bg-transparent text-white text-sm outline-none placeholder:text-gray-600"
                        />
                    </div>
                    {verdictFilter && (
                        <button onClick={() => setVerdictFilter('')} className="flex items-center gap-1 px-2 py-1 rounded-lg text-xs text-gray-400 hover:text-white bg-white/5">
                            <Filter className="w-3 h-3" /> {verdictFilter} <X className="w-3 h-3" />
                        </button>
                    )}
                    <span className="text-xs text-gray-500 shrink-0">{filteredResults.length} results</span>
                </div>

                {filteredResults.length === 0 ? (
                    <div className="text-center py-12 text-gray-600">
                        {run.status === 'running'
                            ? <><Loader2 className="w-5 h-5 mx-auto mb-2 animate-spin" />Checking targets</>
                            : 'No results match filters.'}
                    </div>
                ) : (
                    <div className="divide-y divide-white/[0.03]">
                        {filteredResults.map(result => (
                            <div key={result.id} className="flex items-center justify-between px-4 py-3 hover:bg-white/[0.02] transition-all group">
                                <div className="flex items-center gap-3 min-w-0">
                                    <VerdictBadge verdict={result.verdict} />
                                    <span className="text-gray-300 text-sm font-mono truncate">{result.target_url}</span>
                                </div>
                                <div className="flex items-center gap-3 shrink-0">
                                    <span className="text-gray-600 text-xs max-w-xs truncate hidden md:block">{result.verdict_reason}</span>
                                    <button onClick={() => setDrawerTarget(result)}
                                        className="p-1.5 rounded-lg text-gray-600 hover:text-cyan-400 hover:bg-cyan-500/10 transition-all opacity-0 group-hover:opacity-100">
                                        <Eye className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Evidence drawer */}
            <AnimatePresence>
                {drawerTarget && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-end md:items-center justify-center p-4"
                        onClick={() => setDrawerTarget(null)}>
                        <motion.div
                            initial={{ y: 60, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 60, opacity: 0 }}
                            onClick={e => e.stopPropagation()}
                            className="bg-gray-950 border border-white/[0.08] rounded-2xl w-full max-w-3xl max-h-[85vh] overflow-hidden flex flex-col">
                            <div className="flex items-center justify-between p-4 border-b border-white/[0.06]">
                                <div className="flex items-center gap-3">
                                    <VerdictBadge verdict={drawerTarget.verdict} />
                                    <span className="text-white font-mono text-sm">{drawerTarget.target_url}</span>
                                </div>
                                <button onClick={() => setDrawerTarget(null)} className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-white/5">
                                    <X className="w-4 h-4" />
                                </button>
                            </div>

                            <div className="overflow-y-auto p-4 space-y-4">
                                <div>
                                    <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Verdict Reason</p>
                                    <p className="text-gray-300 text-sm">{drawerTarget.verdict_reason || 'No reason provided'}</p>
                                </div>

                                {/* Per-TTP breakdown */}
                                {drawerTarget.evidence?.per_ttp?.length > 0 && (
                                    <div>
                                        <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Per-TTP Results</p>
                                        <div className="space-y-2">
                                            {drawerTarget.evidence.per_ttp.map((t: any, i: number) => (
                                                <div key={i} className="bg-black/30 rounded-lg p-3">
                                                    <div className="flex items-center gap-2 mb-1.5">
                                                        <VerdictBadge verdict={t.verdict} />
                                                        <span className="text-gray-300 text-sm font-medium">{t.ttp_title}</span>
                                                    </div>
                                                    <p className="text-gray-500 text-xs mb-1.5">{t.reason}</p>
                                                    {t.matched_criteria?.length > 0 && (
                                                        <div className="space-y-1">
                                                            {t.evidence?.map((e: any, j: number) => (
                                                                <div key={j} className={`text-xs flex items-start gap-1.5 ${e.matched ? 'text-green-400' : 'text-gray-600'}`}>
                                                                    <span>{e.matched ? '✓' : '○'}</span>{e.criterion}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {drawerTarget.request_sent && (
                                    <div>
                                        <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Request Sent</p>
                                        <pre className="bg-black/60 rounded-lg p-3 text-xs text-cyan-300 font-mono overflow-x-auto whitespace-pre-wrap">{drawerTarget.request_sent}</pre>
                                    </div>
                                )}

                                {/* Redirect chain */}
                                {drawerTarget.evidence?.redirect_chain?.length > 0 && (
                                    <div>
                                        <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Redirect Chain</p>
                                        <div className="space-y-1.5">
                                            {drawerTarget.evidence.redirect_chain.map((hop: any, i: number) => {
                                                const isOOScope = String(hop.toUrl).includes('[out-of-scope]');
                                                return (
                                                    <div key={i} className={`rounded-lg p-2.5 text-xs font-mono ${isOOScope ? 'bg-red-500/10 border border-red-500/20' : 'bg-black/30'}`}>
                                                        <div className="flex items-center gap-2 flex-wrap">
                                                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${hop.statusCode >= 300 && hop.statusCode < 400 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-500/20 text-gray-400'}`}>
                                                                {hop.statusCode}
                                                            </span>
                                                            <span className="text-gray-400 shrink-0">hop {i + 1}</span>
                                                        </div>
                                                        <div className="mt-1.5 space-y-0.5">
                                                            <p className="text-gray-500 truncate">From: <span className="text-cyan-400">{hop.fromUrl}</span></p>
                                                            <p className={`${isOOScope ? 'text-red-400' : 'text-gray-300'} truncate`}>
                                                                To: {hop.toUrl}
                                                            </p>
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {drawerTarget.response_excerpt && (
                                    <div>
                                        <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Response Excerpt</p>
                                        <pre className="bg-black/60 rounded-lg p-3 text-xs text-gray-300 font-mono overflow-x-auto whitespace-pre-wrap">{drawerTarget.response_excerpt}</pre>
                                    </div>
                                )}
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
