import React, { useState, useEffect, useRef } from 'react';
import { marked } from 'marked';

marked.setOptions({ breaks: true, gfm: true });
import axios from 'axios';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  LayoutDashboard,
  Activity,
  Laptop,
  ShieldAlert,
  Bot,
  Sliders,
  ShieldCheck,
  Radio,
  Search,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  Zap,
  Trash2,
  Database,
  ArrowUpRight,
  ArrowDownLeft,
  Clock,
  Play,
  Square,
  Sparkles,
  Info,
  ChevronRight,
  X,
  Send,
  AlertOctagon,
} from 'lucide-react';

// Register Chart.js
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const API_BASE = import.meta.env.VITE_API_URL || `http://${window.location.hostname || 'localhost'}:8000`;

function formatTime(ts) {
  if (!ts) return '--';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatBytes(bytes) {
  if (bytes == null || isNaN(bytes)) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatBps(bps) {
  if (bps == null || isNaN(bps)) return '0 bps';
  if (bps < 1000) return `${bps.toFixed(0)} bps`;
  if (bps < 1_000_000) return `${(bps / 1000).toFixed(1)} Kbps`;
  return `${(bps / 1_000_000).toFixed(2)} Mbps`;
}

// Global Error Boundary
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error('UI Boundary error:', error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '40px', background: '#0a0d14', color: '#f1f5f9', minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <AlertOctagon size={48} color="#ef4444" style={{ marginBottom: '16px' }} />
          <h2 style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>Interface Rendering Issue</h2>
          <p style={{ color: '#94a3b8', maxWidth: '480px', textAlign: 'center', marginBottom: '20px' }}>
            {this.state.error?.message || 'An unexpected rendering error occurred.'}
          </p>
          <button className="btn btn-primary" onClick={() => { this.setState({ hasError: false }); window.location.reload(); }}>
            <RefreshCw size={14} /> Reload Interface
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <NetWatchApp />
    </ErrorBoundary>
  );
}

function NetWatchApp() {
  // Navigation: overview | traffic | devices | audits | anomalies | ai_copilot | controls
  const [activeNav, setActiveNav] = useState('overview');

  // Core telemetry state
  const [status, setStatus] = useState(null);
  const [traffic, setTraffic] = useState([]);
  const [protocols, setProtocols] = useState(null);
  const [devices, setDevices] = useState([]);
  const [topTalkers, setTopTalkers] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [health, setHealth] = useState(null);
  const [forecast, setForecast] = useState([]);
  const [flows, setFlows] = useState([]);

  // UI state
  const [toasts, setToasts] = useState([]);
  const [copiedText, setCopiedText] = useState(null);
  const [selectedAnomalyForAI, setSelectedAnomalyForAI] = useState(null);
  const [aiAnalysisResult, setAiAnalysisResult] = useState(null);
  const [isAiAnalyzing, setIsAiAnalyzing] = useState(false);

  // Audits state
  const [auditResult, setAuditResult] = useState(null);
  const [isAuditing, setIsAuditing] = useState(false);

  // AI Copilot chat state
  const [chatMessages, setChatMessages] = useState([
    {
      sender: 'ai',
      text: 'Hello! I am your **NetWatch AI Security Copilot**. I analyze real-time network telemetry, assist with incident investigation, and generate defense firewall rules. How can I help secure your network today?',
    },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatThinking, setIsChatThinking] = useState(false);

  // Controls state
  const [modelStatus, setModelStatus] = useState(null);
  const [baselineStatus, setBaselineStatus] = useState(null);
  const [isLearning, setIsLearning] = useState(false);
  const [isScanning, setIsScanning] = useState(false);

  // Toast notification helper
  const addToast = (message, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  const copyToClipboard = (text) => {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        setCopiedText(text);
        addToast('Copied command to clipboard', 'success');
        setTimeout(() => setCopiedText(null), 2000);
      }).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  };

  const fallbackCopy = (text) => {
    try {
      const el = document.createElement('textarea');
      el.value = text;
      el.setAttribute('readonly', '');
      el.style.position = 'absolute';
      el.style.left = '-9999px';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopiedText(text);
      addToast('Copied command to clipboard', 'success');
      setTimeout(() => setCopiedText(null), 2000);
    } catch (_) {
      addToast('Failed to copy', 'error');
    }
  };

  // Main data polling (every 3s)
  const fetchData = async () => {
    try {
      const [
        statusRes,
        trafficRes,
        protoRes,
        devRes,
        talkerRes,
        alertsRes,
        healthRes,
        forecastRes,
      ] = await Promise.all([
        axios.get(`${API_BASE}/api/status`, { timeout: 2500 }).catch(() => ({ data: null })),
        axios.get(`${API_BASE}/api/traffic?minutes=15`, { timeout: 2500 }).catch(() => ({ data: { points: [] } })),
        axios.get(`${API_BASE}/api/protocols?minutes=5`, { timeout: 2500 }).catch(() => ({ data: null })),
        axios.get(`${API_BASE}/api/devices`, { timeout: 2500 }).catch(() => ({ data: [] })),
        axios.get(`${API_BASE}/api/top-talkers?minutes=5&limit=10`, { timeout: 2500 }).catch(() => ({ data: [] })),
        axios.get(`${API_BASE}/api/alerts?limit=50`, { timeout: 2500 }).catch(() => ({ data: [] })),
        axios.get(`${API_BASE}/api/health`, { timeout: 2500 }).catch(() => ({ data: null })),
        axios.get(`${API_BASE}/api/forecast`, { timeout: 2500 }).catch(() => ({ data: { points: [] } })),
      ]);

      if (statusRes.data) setStatus(statusRes.data);
      if (trafficRes.data?.points) setTraffic(trafficRes.data.points);
      if (protoRes.data) setProtocols(protoRes.data);
      if (devRes.data) setDevices(devRes.data);
      if (talkerRes.data) setTopTalkers(talkerRes.data);
      if (alertsRes.data) setAlerts(alertsRes.data);
      if (healthRes.data) setHealth(healthRes.data);
      if (forecastRes.data?.points) setForecast(forecastRes.data.points);
    } catch (e) {
      console.warn('Data sync pause:', e);
    }
  };

  useEffect(() => {
    fetchData();
    const timer = setInterval(fetchData, 3000);
    return () => clearInterval(timer);
  }, []);

  // Fetch packet flows stream when Traffic tab is active
  useEffect(() => {
    if (activeNav !== 'traffic') return;
    const fetchFlows = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/flows?limit=30`, { timeout: 2500 });
        setFlows(res.data || []);
      } catch (_) {}
    };
    fetchFlows();
    const t = setInterval(fetchFlows, 3000);
    return () => clearInterval(t);
  }, [activeNav]);

  // Model status poll
  useEffect(() => {
    const fetchModelStatus = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/model/status`, { timeout: 2500 });
        setModelStatus(res.data);
      } catch (_) {}
    };
    fetchModelStatus();
    const t = setInterval(fetchModelStatus, 5000);
    return () => clearInterval(t);
  }, []);

  // Baseline learning poll
  useEffect(() => {
    if (!isLearning) return;
    const fetchBaseline = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/baseline/status`, { timeout: 2500 });
        setBaselineStatus(res.data);
        if (res.data?.status === 'done' || res.data?.progress_pct >= 100) {
          setIsLearning(false);
          addToast('Baseline recording finished! You can train the model now.', 'success');
        }
      } catch (_) {}
    };
    fetchBaseline();
    const t = setInterval(fetchBaseline, 3000);
    return () => clearInterval(t);
  }, [isLearning]);

  // Actions
  const handleToggleKnown = async (mac) => {
    try {
      const res = await axios.post(`${API_BASE}/api/devices/${encodeURIComponent(mac)}/known`);
      setDevices((prev) =>
        prev.map((d) => (d.mac.toLowerCase() === mac.toLowerCase() ? { ...d, is_known: res.data.is_known } : d))
      );
      addToast(`Device ${res.data.is_known === 1 ? 'marked as Trusted Baseline' : 'marked as Untrusted'}`, 'info');
    } catch (err) {
      addToast(`Failed to toggle whitelist: ${err.message}`, 'error');
    }
  };

  const handleAcknowledgeAlert = async (id) => {
    try {
      await axios.post(`${API_BASE}/api/alerts/${id}/ack`);
      setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, acknowledged: 1 } : a)));
      addToast('Alert marked as resolved', 'success');
    } catch (err) {
      addToast(`Failed: ${err.message}`, 'error');
    }
  };

  const handleRunSecurityAudit = async (checkType = 'all') => {
    setIsAuditing(true);
    addToast('Executing defensive security audit across live traffic...', 'info');
    try {
      const res = await axios.post(`${API_BASE}/api/security/audit`, { check_type: checkType }, { timeout: 15000 });
      setAuditResult(res.data);
      addToast(`Security Audit Complete: Score ${res.data?.security_score}/100 (${res.data?.posture_label})`, 'success');
    } catch (err) {
      addToast(`Audit failed: ${err.message}`, 'error');
    } finally {
      setIsAuditing(false);
    }
  };

  const handleAnalyzeWithAI = async (alert) => {
    setSelectedAnomalyForAI(alert);
    setIsAiAnalyzing(true);
    try {
      const res = await axios.post(`${API_BASE}/api/ai/analyze`, { alert_id: alert.id, alert }, { timeout: 30000 });
      setAiAnalysisResult(res.data);
    } catch (err) {
      addToast(`AI Analysis failed: ${err.message}`, 'error');
    } finally {
      setIsAiAnalyzing(false);
    }
  };

  const handleSendChatMessage = async (e) => {
    if (e) e.preventDefault();
    if (!chatInput.trim() || isChatThinking) return;

    const userText = chatInput.trim();
    setChatMessages((prev) => [...prev, { sender: 'user', text: userText }]);
    setChatInput('');
    setIsChatThinking(true);

    try {
      const res = await axios.post(`${API_BASE}/api/ai/chat`, { message: userText }, { timeout: 30000 });
      setChatMessages((prev) => [...prev, { sender: 'ai', text: res.data?.reply || 'No response.' }]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        { sender: 'ai', text: `❌ Could not reach AI Copilot service: ${err.message}` },
      ]);
    } finally {
      setIsChatThinking(false);
    }
  };

  const handleStartCapture = async () => {
    try {
      await axios.post(`${API_BASE}/api/capture/start`);
      addToast('Packet capture set to active', 'success');
      fetchData();
    } catch (err) {
      addToast(`Failed: ${err.message}`, 'error');
    }
  };

  const handleStopCapture = async () => {
    try {
      await axios.post(`${API_BASE}/api/capture/stop`);
      addToast('Packet capture paused', 'info');
      fetchData();
    } catch (err) {
      addToast(`Failed: ${err.message}`, 'error');
    }
  };

  const handleScanSubnet = async () => {
    setIsScanning(true);
    addToast('Broadcasting high-speed ARP sweep across subnet...', 'info');
    try {
      const res = await axios.post(`${API_BASE}/api/discovery/scan?wait=true`, {}, { timeout: 15000 });
      if (res.data?.devices) {
        setDevices(res.data.devices);
      }
      await fetchData();
      addToast(`Network scan complete! ${res.data?.count || res.data?.devices?.length || 0} active devices identified.`, 'success');
    } catch (err) {
      addToast(`Scan error: ${err.message}`, 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleTrustAllDevices = async () => {
    try {
      const res = await axios.post(`${API_BASE}/api/devices/baseline`);
      addToast(res.data?.message || 'All current devices marked as trusted baseline.', 'success');
      fetchData();
    } catch (err) {
      addToast(`Failed: ${err.message}`, 'error');
    }
  };

  const handleResetDatabase = async () => {
    if (!window.confirm('Wipe telemetry tables, simulated flows, and reset alerts? This starts a pristine capture session.')) return;
    try {
      const res = await axios.post(`${API_BASE}/api/database/reset?clear_devices=false`);
      addToast('Database reset to pristine state.', 'success');
      setAlerts([]);
      setTraffic([]);
      setFlows([]);
      fetchData();
    } catch (err) {
      addToast(`Reset failed: ${err.message}`, 'error');
    }
  };

  const handleTrainModel = async () => {
    addToast('Training Isolation Forest pipeline on baseline...', 'info');
    try {
      const res = await axios.post(`${API_BASE}/api/model/train`);
      addToast(res.data?.message || 'Model trained successfully! Switching to Hybrid ML Mode.', 'success');
      fetchData();
    } catch (err) {
      addToast(`Training failed: ${err.message}`, 'error');
    }
  };

  // Metrics
  const activeDeviceCount = devices.filter((d) => d.status === 'online').length;
  const unknownDeviceCount = devices.filter((d) => d.is_known === 0 && d.status === 'online').length;
  const unackAlertCount = alerts.filter((a) => a.acknowledged === 0).length;
  const latestTraffic = traffic.length > 0 ? traffic[traffic.length - 1] : null;
  const healthScore = health?.score ?? 100;
  const healthLabel = health?.label || 'Healthy';

  // Chart data
  const trafficLabels = traffic.map((p) => formatTime(p.ts));
  const forecastLabels = forecast.map((p) => formatTime(p.ts));
  const allLabels = [...trafficLabels, ...forecastLabels];

  const bandwidthChartData = {
    labels: allLabels,
    datasets: [
      {
        label: 'Inbound (bps)',
        data: traffic.map((p) => p.bps_in),
        borderColor: '#10b981',
        backgroundColor: 'rgba(16, 185, 129, 0.08)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 0,
      },
      {
        label: 'Outbound (bps)',
        data: traffic.map((p) => p.bps_out),
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.08)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 0,
      },
      {
        label: 'Projected Demand (5m)',
        data: [
          ...Array(traffic.length).fill(null),
          ...forecast.map((p) => p.predicted_bps),
        ],
        borderColor: '#f59e0b',
        borderDash: [5, 5],
        borderWidth: 2,
        pointRadius: 0,
        fill: false,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: {
        position: 'top',
        labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' }, boxWidth: 12, usePointStyle: true },
      },
      tooltip: {
        backgroundColor: '#111726',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        titleColor: '#fff',
        bodyColor: '#94a3b8',
        callbacks: {
          label: (ctx) => `${ctx.dataset.label}: ${formatBps(ctx.raw)}`,
        },
      },
    },
    scales: {
      x: {
        ticks: { color: '#64748b', font: { size: 10 }, maxTicksLimit: 8 },
        grid: { color: 'rgba(255, 255, 255, 0.03)' },
      },
      y: {
        ticks: { color: '#64748b', font: { size: 10 }, callback: (v) => formatBps(v) },
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
      },
    },
  };

  const protoDoughnutData = {
    labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'Other'],
    datasets: [
      {
        data: [
          protocols?.tcp_pct ?? 60,
          protocols?.udp_pct ?? 25,
          protocols?.icmp_pct ?? 5,
          protocols?.dns_pct ?? 8,
          protocols?.other_pct ?? 2,
        ],
        backgroundColor: ['#38bdf8', '#10b981', '#ef4444', '#f59e0b', '#64748b'],
        borderWidth: 0,
      },
    ],
  };

  return (
    <div className="layout-container">
      {/* ── Fixed Sidebar Navigation ────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo-badge">
            <Radio size={20} />
          </div>
          <div className="brand-text">
            <h1>NetWatch</h1>
            <span>AI NOC & SOC Defense</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button
            className={`nav-item ${activeNav === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveNav('overview')}
          >
            <LayoutDashboard size={18} />
            <span>Overview</span>
          </button>

          <button
            className={`nav-item ${activeNav === 'traffic' ? 'active' : ''}`}
            onClick={() => setActiveNav('traffic')}
          >
            <Activity size={18} />
            <span>Traffic Inspector</span>
          </button>

          <button
            className={`nav-item ${activeNav === 'devices' ? 'active' : ''}`}
            onClick={() => setActiveNav('devices')}
          >
            <Laptop size={18} />
            <span>Device Matrix</span>
            {unknownDeviceCount > 0 && <span className="nav-badge">{unknownDeviceCount}</span>}
          </button>

          <button
            className={`nav-item ${activeNav === 'audits' ? 'active' : ''}`}
            onClick={() => setActiveNav('audits')}
          >
            <ShieldCheck size={18} />
            <span>Defensive Audits</span>
          </button>

          <button
            className={`nav-item ${activeNav === 'anomalies' ? 'active' : ''}`}
            onClick={() => setActiveNav('anomalies')}
          >
            <ShieldAlert size={18} />
            <span>Threat Center</span>
            {unackAlertCount > 0 && <span className="nav-badge">{unackAlertCount}</span>}
          </button>

          <button
            className={`nav-item ${activeNav === 'ai_copilot' ? 'active' : ''}`}
            onClick={() => setActiveNav('ai_copilot')}
          >
            <Bot size={18} />
            <span>AI Security Copilot</span>
          </button>

          <button
            className={`nav-item ${activeNav === 'controls' ? 'active' : ''}`}
            onClick={() => setActiveNav('controls')}
          >
            <Sliders size={18} />
            <span>Operations & Control</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div>MONITORED INTERFACE</div>
          <div className="network-pill">
            <div className="pulse-dot" />
            <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              <strong style={{ color: '#f1f5f9' }}>{status?.interface || 'Auto'}</strong>
              <div style={{ fontSize: '10px' }}>{status?.subnet || 'Detecting...'}</div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Content Area ───────────────────────────────────────────── */}
      <main className="main-content">
        {/* Top Header Bar */}
        <header className="header-bar">
          <div className="header-left">
            <h2>
              {activeNav === 'overview' && 'Network Operations Overview'}
              {activeNav === 'traffic' && 'Deep Traffic Telemetry & Flows'}
              {activeNav === 'devices' && 'Subnet Host & Device Matrix'}
              {activeNav === 'audits' && 'Defensive Attack & Vulnerability Audits'}
              {activeNav === 'anomalies' && 'Threat Intelligence & Anomaly Hub'}
              {activeNav === 'ai_copilot' && 'NetWatch Security SLM Copilot'}
              {activeNav === 'controls' && 'System Management & Pipeline Controls'}
            </h2>
            <p>
              Local Host: <span className="mono" style={{ color: '#38bdf8' }}>{status?.gateway ? `${status.subnet} (GW: ${status.gateway})` : 'Initializing'}</span>
            </p>
          </div>

          <div className="header-actions">
            <div className="live-indicator">
              <span className="pulse-dot" />
              <span>{status?.capture_running ? 'Sniffer Active' : 'Idle'}</span>
            </div>

            <div
              className="badge"
              style={{
                background: healthScore >= 80 ? 'rgba(16, 185, 129, 0.15)' : healthScore >= 50 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                color: healthScore >= 80 ? '#10b981' : healthScore >= 50 ? '#f59e0b' : '#ef4444',
                padding: '6px 14px',
                borderRadius: '20px',
                fontWeight: 700,
                fontSize: '12px',
              }}
            >
              {healthScore.toFixed(0)}% {healthLabel}
            </div>

            <button
              className="btn btn-primary btn-sm"
              onClick={handleScanSubnet}
              disabled={isScanning}
              style={{
                boxShadow: '0 0 14px rgba(2, 132, 199, 0.4)',
                border: '1px solid rgba(56, 189, 248, 0.4)',
              }}
              title="Immediately rescan the network for newly connected phones or devices"
            >
              <RefreshCw size={13} className={isScanning ? 'spin' : ''} />
              <span>{isScanning ? 'Scanning Network...' : 'Refresh Network'}</span>
            </button>

            <button className="btn btn-secondary btn-sm" onClick={() => handleRunSecurityAudit('all')} disabled={isAuditing}>
              <ShieldCheck size={14} color="#38bdf8" />
              <span>{isAuditing ? 'Auditing...' : 'Run Quick Audit'}</span>
            </button>
          </div>
        </header>

        {/* Page Content Body */}
        <div className="page-body">
          {/* ══════════════════════════════════════════════════════════════════
              PAGE 1: OVERVIEW DASHBOARD
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'overview' && (
            <div>
              {/* Executive Stat Cards */}
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-header">
                    <span className="stat-label">Network Health</span>
                    <div className="stat-icon" style={{ color: '#10b981' }}><ShieldCheck size={18} /></div>
                  </div>
                  <div className="stat-value" style={{ color: healthScore >= 80 ? '#10b981' : '#f59e0b' }}>
                    {healthScore.toFixed(1)}
                  </div>
                  <div className="stat-sub">
                    <CheckCircle2 size={13} color="#10b981" />
                    <span>{unackAlertCount} active security incidents</span>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-header">
                    <span className="stat-label">Throughput In / Out</span>
                    <div className="stat-icon" style={{ color: '#38bdf8' }}><Activity size={18} /></div>
                  </div>
                  <div className="stat-value">
                    {formatBps((latestTraffic?.bps_in || 0) + (latestTraffic?.bps_out || 0))}
                  </div>
                  <div className="stat-sub">
                    <span style={{ color: '#10b981' }}>↓ {formatBps(latestTraffic?.bps_in || 0)}</span>
                    <span style={{ color: '#38bdf8', marginLeft: '8px' }}>↑ {formatBps(latestTraffic?.bps_out || 0)}</span>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-header">
                    <span className="stat-label">Gateway Round-Trip</span>
                    <div className="stat-icon" style={{ color: '#a855f7' }}><Clock size={18} /></div>
                  </div>
                  <div className="stat-value">
                    {latestTraffic?.latency_ms != null ? `${latestTraffic.latency_ms.toFixed(1)} ms` : '--'}
                  </div>
                  <div className="stat-sub">
                    <span>Packet Loss: <strong style={{ color: (latestTraffic?.loss_pct || 0) > 5 ? '#ef4444' : '#10b981' }}>{latestTraffic?.loss_pct ?? 0}%</strong></span>
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-header">
                    <span className="stat-label">Discovered Hosts</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <button
                        onClick={handleScanSubnet}
                        disabled={isScanning}
                        style={{
                          background: 'rgba(56, 189, 248, 0.1)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          borderRadius: '6px',
                          color: '#38bdf8',
                          cursor: 'pointer',
                          padding: '4px 8px',
                          fontSize: '11px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                        title="Rescan subnet now"
                      >
                        <RefreshCw size={11} className={isScanning ? 'spin' : ''} />
                        <span>Scan</span>
                      </button>
                      <div className="stat-icon" style={{ color: '#f59e0b' }}><Laptop size={18} /></div>
                    </div>
                  </div>
                  <div className="stat-value">
                    {activeDeviceCount} <span style={{ fontSize: '15px', color: '#64748b' }}>/ {devices.length}</span>
                  </div>
                  <div className="stat-sub">
                    {unknownDeviceCount > 0 ? (
                      <span style={{ color: '#f59e0b' }}>⚠️ {unknownDeviceCount} unverified device(s)</span>
                    ) : (
                      <span style={{ color: '#10b981' }}>✓ All devices baseline trusted</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Main Charts */}
              <div className="charts-grid">
                <div className="card">
                  <div className="card-header">
                    <div>
                      <h3 className="card-title"><Activity size={16} color="#38bdf8" /> Bandwidth Telemetry & Machine Learning Forecast</h3>
                      <p className="card-subtitle">Real-time throughput sliding window (5s) with 5-minute projected demand</p>
                    </div>
                  </div>
                  <div style={{ height: '280px' }}>
                    <Line data={bandwidthChartData} options={chartOptions} />
                  </div>
                </div>

                <div className="card">
                  <div className="card-header">
                    <div>
                      <h3 className="card-title"><Radio size={16} color="#a855f7" /> Protocol Distribution</h3>
                      <p className="card-subtitle">Packet volume share across layers</p>
                    </div>
                  </div>
                  <div style={{ height: '240px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Doughnut data={protoDoughnutData} options={{ maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 10 } } } }} />
                  </div>
                </div>
              </div>

              {/* Quick Threat & Talkers Row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div className="card">
                  <div className="card-header">
                    <h3 className="card-title"><ShieldAlert size={16} color="#ef4444" /> Active Threat Feed</h3>
                    <button className="btn btn-secondary btn-sm" onClick={() => setActiveNav('anomalies')}>
                      View All
                    </button>
                  </div>
                  {alerts.length === 0 ? (
                    <div style={{ padding: '30px', textAlign: 'center', color: '#64748b' }}>
                      <CheckCircle2 size={32} color="#10b981" style={{ margin: '0 auto 10px' }} />
                      <p>No active security threats or anomalies detected.</p>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {alerts.slice(0, 3).map((a) => (
                        <div key={a.id} style={{ background: '#111726', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '12px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <span className={`badge ${a.severity === 'high' ? 'badge-red' : 'badge-amber'}`}>{a.alert_type}</span>
                            <span style={{ fontSize: '11px', color: '#64748b' }}>{formatTime(a.ts)}</span>
                          </div>
                          <p style={{ fontSize: '12px', color: '#f1f5f9', margin: '4px 0' }}>{a.message}</p>
                          <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                            <button className="btn btn-secondary btn-sm" onClick={() => handleAnalyzeWithAI(a)}>
                              <Bot size={12} color="#38bdf8" /> Analyze with SLM
                            </button>
                            <button className="btn btn-secondary btn-sm" onClick={() => handleAcknowledgeAlert(a.id)}>
                              Resolve
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="card">
                  <div className="card-header">
                    <h3 className="card-title"><Zap size={16} color="#f59e0b" /> Highest Bandwidth Consumers</h3>
                    <button className="btn btn-secondary btn-sm" onClick={() => setActiveNav('traffic')}>
                      Inspect
                    </button>
                  </div>
                  <div className="table-wrapper">
                    <table>
                      <thead>
                        <tr>
                          <th>Host</th>
                          <th>Upload</th>
                          <th>Download</th>
                          <th>Total</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topTalkers.length === 0 ? (
                          <tr><td colSpan={4} style={{ textAlign: 'center', color: '#64748b' }}>Awaiting traffic flows...</td></tr>
                        ) : (
                          topTalkers.slice(0, 4).map((t, i) => (
                            <tr key={i}>
                              <td>
                                <strong style={{ color: '#fff' }}>{t.host}</strong>
                                {t.hostname && <div style={{ fontSize: '11px', color: '#64748b' }}>{t.hostname}</div>}
                              </td>
                              <td style={{ color: '#10b981' }}>{formatBytes(t.bytes_out)}</td>
                              <td style={{ color: '#38bdf8' }}>{formatBytes(t.bytes_in)}</td>
                              <td><strong>{formatBytes(t.total_bytes)}</strong></td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              PAGE 2: TRAFFIC INSPECTOR
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'traffic' && (
            <div>
              <div className="card">
                <div className="card-header">
                  <div>
                    <h3 className="card-title"><Activity size={18} color="#38bdf8" /> Real-Time Ingress & Egress Analysis</h3>
                    <p className="card-subtitle">Throughput metrics sampled across discrete 5-second collection windows</p>
                  </div>
                </div>
                <div style={{ height: '300px' }}>
                  <Line data={bandwidthChartData} options={chartOptions} />
                </div>
              </div>

              {/* Raw Packet Stream Table */}
              <div className="card">
                <div className="card-header">
                  <div>
                    <h3 className="card-title"><Terminal size={18} color="#10b981" /> Deep Packet Flow Stream</h3>
                    <p className="card-subtitle">Live stream of captured frames arriving on {status?.interface || 'interface'}</p>
                  </div>
                  <span className="badge badge-green">LIVE STREAMING</span>
                </div>

                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Protocol</th>
                        <th>Source IP : Port</th>
                        <th>Destination IP : Port</th>
                        <th>Frame Size</th>
                        <th>TCP Flags</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flows.length === 0 ? (
                        <tr><td colSpan={6} style={{ textAlign: 'center', color: '#64748b', padding: '30px' }}>Listening for live packet flows on {status?.interface}...</td></tr>
                      ) : (
                        flows.slice(0, 20).map((f) => (
                          <tr key={f.id}>
                            <td className="mono" style={{ fontSize: '11px', color: '#94a3b8' }}>{formatTime(f.ts)}</td>
                            <td>
                              <span className={`badge ${f.protocol === 'TCP' ? 'badge-blue' : f.protocol === 'UDP' ? 'badge-green' : f.protocol === 'ICMP' ? 'badge-red' : 'badge-gray'}`}>
                                {f.protocol}
                              </span>
                            </td>
                            <td className="mono" style={{ color: '#f1f5f9' }}>{f.src_ip}{f.src_port ? `:${f.src_port}` : ''}</td>
                            <td className="mono" style={{ color: '#cbd5e1' }}>{f.dst_ip}{f.dst_port ? `:${f.dst_port}` : ''}</td>
                            <td>{f.length} B</td>
                            <td className="mono" style={{ color: f.tcp_flags?.includes('S') && !f.tcp_flags?.includes('A') ? '#f59e0b' : '#64748b' }}>
                              {f.tcp_flags || '--'}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Top Talkers Table */}
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title"><Zap size={18} color="#f59e0b" /> Bandwidth Consumption by Host</h3>
                </div>
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>Host Address</th>
                        <th>Hostname</th>
                        <th>Uploaded</th>
                        <th>Downloaded</th>
                        <th>Total Volume</th>
                        <th>Average PPS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topTalkers.map((t, idx) => (
                        <tr key={idx}>
                          <td className="mono" style={{ color: '#38bdf8', fontWeight: 600 }}>{t.ip || t.host}</td>
                          <td>
                            <div style={{ fontWeight: 500, color: '#f1f5f9' }}>{t.hostname || 'External Cloud Host'}</div>
                            {t.vendor && <div style={{ fontSize: '11px', color: '#64748b' }}>{t.vendor}</div>}
                          </td>
                          <td style={{ color: '#10b981' }}>{formatBytes(t.bytes_out)}</td>
                          <td style={{ color: '#38bdf8' }}>{formatBytes(t.bytes_in)}</td>
                          <td><strong>{formatBytes(t.total_bytes)}</strong></td>
                          <td style={{ color: '#94a3b8' }}>{(t.avg_pps ?? t.pps ?? 0).toFixed(1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              PAGE 3: DEVICE MATRIX
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'devices' && (
            <div>
              <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                <div>
                  <h3 className="card-title"><Laptop size={18} color="#38bdf8" /> Local Subnet Topology ({status?.subnet || 'Auto'})</h3>
                  <p className="card-subtitle">Autonomous host inventory with offline IEEE MAC OUI vendor resolution</p>
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button className="btn btn-secondary" onClick={handleScanSubnet} disabled={isScanning}>
                    <RefreshCw size={14} className={isScanning ? 'spin' : ''} />
                    <span>{isScanning ? 'Sweeping Subnet...' : 'Scan Subnet Now'}</span>
                  </button>
                  <button className="btn btn-primary" onClick={handleTrustAllDevices}>
                    <ShieldCheck size={14} />
                    <span>Trust All Devices</span>
                  </button>
                </div>
              </div>

              <div className="card">
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Manufacturer / Vendor</th>
                        <th>Hostname</th>
                        <th>Status</th>
                        <th>Whitelist Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {devices.length === 0 ? (
                        <tr><td colSpan={7} style={{ textAlign: 'center', color: '#64748b', padding: '30px' }}>No hosts discovered. Run a subnet scan above.</td></tr>
                      ) : (
                        devices.map((d) => (
                          <tr key={d.mac}>
                            <td className="mono" style={{ fontWeight: 600, color: '#f1f5f9' }}>{d.ip}</td>
                            <td className="mono" style={{ color: '#94a3b8' }}>{d.mac}</td>
                            <td>
                              <span className="badge badge-gray">{d.vendor || 'Generic'}</span>
                            </td>
                            <td><strong style={{ color: '#f1f5f9' }}>{d.hostname || 'Subnet Device'}</strong></td>
                            <td>
                              <span className={`badge ${d.status === 'online' ? 'badge-green' : 'badge-gray'}`}>
                                {d.status}
                              </span>
                            </td>
                            <td>
                              <span className={`badge ${d.is_known === 1 ? 'badge-blue' : 'badge-amber'}`}>
                                {d.is_known === 1 ? '✓ Trusted' : '⚠️ Untrusted'}
                              </span>
                            </td>
                            <td>
                              <button
                                className={`btn btn-sm ${d.is_known === 1 ? 'btn-secondary' : 'btn-primary'}`}
                                onClick={() => handleToggleKnown(d.mac)}
                              >
                                {d.is_known === 1 ? 'Revoke Trust' : 'Trust Device'}
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              PAGE 4: DEFENSIVE SECURITY AUDITS (Attack Check Hub)
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'audits' && (
            <div>
              <div className="card">
                <div className="card-header">
                  <div>
                    <h3 className="card-title"><ShieldCheck size={20} color="#10b981" /> Defensive Attack & Vulnerability Audit Engine</h3>
                    <p className="card-subtitle">
                      Runs automated real-time heuristic & behavioral scans against your network traffic to verify if your host is under attack.
                    </p>
                  </div>
                  <button className="btn btn-primary" onClick={() => handleRunSecurityAudit('all')} disabled={isAuditing}>
                    <ShieldCheck size={16} />
                    <span>{isAuditing ? 'Auditing Traffic...' : 'Run Comprehensive Audit'}</span>
                  </button>
                </div>

                {auditResult && (
                  <div
                    style={{
                      background: auditResult.color + '15',
                      border: `1px solid ${auditResult.color}50`,
                      borderRadius: '10px',
                      padding: '20px',
                      marginBottom: '20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '16px',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '12px', fontWeight: 700, color: auditResult.color, textTransform: 'uppercase', letterSpacing: '0.8px' }}>
                        Security Defense Posture
                      </div>
                      <div style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginTop: '4px' }}>
                        {auditResult.posture_label}
                      </div>
                      <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px' }}>
                        Audited {auditResult.checks_performed} vectors on interface <strong>{auditResult.target_interface}</strong> ({auditResult.target_subnet})
                      </div>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '36px', fontWeight: 800, color: auditResult.color }}>
                        {auditResult.security_score}<span style={{ fontSize: '18px', color: '#64748b' }}>/100</span>
                      </div>
                      <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                        {auditResult.passed_checks} Passed · {auditResult.warning_checks} Warnings · {auditResult.critical_checks} Critical
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* 6 Automated Check Cards */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {(auditResult?.checks || [
                  { check: 'syn_flood', name: 'TCP SYN Flood Defense Audit', status: 'PASS', summary: 'Checks for half-open unacknowledged TCP SYN connection floods.' },
                  { check: 'port_scan', name: 'Port Scanning & Reconnaissance Audit', status: 'PASS', summary: 'Detects rapid horizontal and vertical port scanning probes.' },
                  { check: 'icmp_flood', name: 'ICMP Storm / Ping Flood Audit', status: 'PASS', summary: 'Detects high-frequency ping burst and DoS bandwidth saturation.' },
                  { check: 'bandwidth_drain', name: 'Bandwidth Drain & Exfiltration Audit', status: 'PASS', summary: 'Identifies abnormal sustained upload surges exceeding baselines.' },
                  { check: 'arp_spoof', name: 'ARP Poisoning & MITM Verification', status: 'PASS', summary: 'Verifies MAC integrity of default gateway to prevent MITM interception.' },
                  { check: 'rogue_device', name: 'Rogue Host Infiltration Audit', status: 'PASS', summary: 'Flags unverified hardware addresses operating on your subnet.' },
                ]).map((c, i) => (
                  <div key={i} className={`audit-check-card ${c.status}`}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        {c.status === 'PASS' && <CheckCircle2 size={18} color="#10b981" />}
                        {c.status === 'WARNING' && <AlertTriangle size={18} color="#f59e0b" />}
                        {c.status === 'CRITICAL' && <XCircle size={18} color="#ef4444" />}
                        <strong style={{ fontSize: '14px', color: '#fff' }}>{c.name}</strong>
                      </div>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span className={`badge ${c.status === 'PASS' ? 'badge-green' : c.status === 'WARNING' ? 'badge-amber' : 'badge-red'}`}>
                          {c.status}
                        </span>
                        <button className="btn btn-secondary btn-sm" onClick={() => handleRunSecurityAudit(c.check)} disabled={isAuditing}>
                          Re-check
                        </button>
                      </div>
                    </div>

                    <p style={{ fontSize: '13px', color: '#94a3b8', margin: '4px 0' }}>{c.summary}</p>

                    {c.remediation && (
                      <div style={{ marginTop: '10px', background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                        <div style={{ fontSize: '11px', fontWeight: 700, color: '#38bdf8', marginBottom: '8px', textTransform: 'uppercase' }}>
                          Recommended Remediation Command:
                        </div>
                        {c.remediation.windows && (
                          <div className="code-box" style={{ marginBottom: '6px' }}>
                            <span>{c.remediation.windows}</span>
                            <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(c.remediation.windows)}>
                              <Copy size={12} />
                            </button>
                          </div>
                        )}
                        {c.remediation.linux && (
                          <div className="code-box">
                            <span>{c.remediation.linux}</span>
                            <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(c.remediation.linux)}>
                              <Copy size={12} />
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              PAGE 5: THREAT & ANOMALY CENTER
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'anomalies' && (
            <div>
              <div className="card">
                <div className="card-header">
                  <div>
                    <h3 className="card-title"><ShieldAlert size={18} color="#ef4444" /> Security Incident Feed & Anomaly Center</h3>
                    <p className="card-subtitle">Machine learning statistical outliers and deterministic attack signatures</p>
                  </div>
                  <span className="badge badge-amber">{unackAlertCount} Unresolved</span>
                </div>

                {alerts.length === 0 ? (
                  <div style={{ padding: '60px 20px', textAlign: 'center', color: '#64748b' }}>
                    <ShieldCheck size={48} color="#10b981" style={{ margin: '0 auto 12px' }} />
                    <h4 style={{ fontSize: '16px', color: '#fff', marginBottom: '6px' }}>Clean Network Baseline</h4>
                    <p>No anomalous patterns, intrusions, or security threats detected.</p>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {alerts.map((a) => (
                      <div
                        key={a.id}
                        style={{
                          background: '#111726',
                          border: `1px solid ${a.acknowledged ? 'rgba(255,255,255,0.06)' : a.severity === 'high' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)'}`,
                          borderRadius: '10px',
                          padding: '16px 20px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '10px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <span className={`badge ${a.severity === 'high' ? 'badge-red' : a.severity === 'medium' ? 'badge-amber' : 'badge-blue'}`}>
                              {a.severity.toUpperCase()}
                            </span>
                            <span className="badge badge-gray">{a.alert_type}</span>
                            <strong style={{ color: '#fff' }}>Host: {a.src_ip}</strong>
                          </div>
                          <div style={{ fontSize: '12px', color: '#64748b' }}>
                            {formatTime(a.ts)} · Score: {(a.score * 100).toFixed(0)}%
                          </div>
                        </div>

                        <p style={{ fontSize: '13px', color: '#f1f5f9' }}>{a.message}</p>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                          <div style={{ display: 'flex', gap: '8px' }}>
                            <button className="btn btn-primary btn-sm" onClick={() => handleAnalyzeWithAI(a)}>
                              <Bot size={13} />
                              <span>Analyze with AI Copilot</span>
                            </button>
                            <button className="btn btn-secondary btn-sm" onClick={() => copyToClipboard(`New-NetFirewallRule -DisplayName "Block-${a.src_ip}" -RemoteAddress ${a.src_ip} -Action Block`)}>
                              <Copy size={13} />
                              <span>Copy Block Rule</span>
                            </button>
                          </div>

                          {!a.acknowledged && (
                            <button className="btn btn-secondary btn-sm" onClick={() => handleAcknowledgeAlert(a.id)}>
                              Dismiss / Resolve
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              PAGE 6: AI SECURITY COPILOT
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'ai_copilot' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div className="card">
                  <h3 className="card-title"><Bot size={18} color="#38bdf8" /> Live Threat Intelligence</h3>
                  <p className="card-subtitle">Real-time situational awareness feeding the model</p>
                  <div style={{ marginTop: '14px', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#94a3b8' }}>Interface:</span>
                      <span className="mono" style={{ color: '#fff' }}>{status?.interface}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#94a3b8' }}>Local Subnet:</span>
                      <span className="mono" style={{ color: '#fff' }}>{status?.subnet}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#94a3b8' }}>Gateway Address:</span>
                      <span className="mono" style={{ color: '#fff' }}>{status?.gateway || 'Auto'}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#94a3b8' }}>Active Incidents:</span>
                      <span style={{ color: unackAlertCount > 0 ? '#ef4444' : '#10b981', fontWeight: 600 }}>
                        {unackAlertCount} unresolved
                      </span>
                    </div>
                  </div>
                </div>

                <div className="card">
                  <h4 style={{ fontSize: '13px', fontWeight: 600, color: '#fff', marginBottom: '10px' }}>Quick Prompts</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {[
                      'Is my network currently secure?',
                      'How do I stop a SYN flood on Windows?',
                      'Explain how to block port scanners',
                      'What should I do about unknown devices?',
                    ].map((prompt, idx) => (
                      <button
                        key={idx}
                        className="btn btn-secondary btn-sm"
                        style={{ textAlign: 'left', justifyContent: 'flex-start' }}
                        onClick={() => {
                          setChatInput(prompt);
                        }}
                      >
                        <ChevronRight size={12} color="#38bdf8" />
                        <span>{prompt}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Chat Column */}
              <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '620px' }}>
                <div className="card-header">
                  <h3 className="card-title"><Sparkles size={16} color="#38bdf8" /> NetWatch Security Copilot</h3>
                  <span className="badge badge-blue">SLM Defense Engine</span>
                </div>

                <div style={{ flex: 1, overflowY: 'auto', padding: '10px 0', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {chatMessages.map((msg, i) => (
                    <div
                      key={i}
                      style={{
                        alignSelf: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                        maxWidth: '88%',
                        background: msg.sender === 'user' ? '#0284c7' : '#172033',
                        color: '#fff',
                        padding: '12px 18px',
                        borderRadius: '14px',
                        border: msg.sender === 'user' ? 'none' : '1px solid rgba(255,255,255,0.08)',
                        boxShadow: '0 4px 14px rgba(0,0,0,0.2)',
                      }}
                    >
                      {msg.sender === 'user' ? (
                        <div style={{ whiteSpace: 'pre-wrap', fontSize: '13.5px' }}>{msg.text}</div>
                      ) : (
                        <div
                          className="markdown-content"
                          dangerouslySetInnerHTML={{ __html: marked.parse(msg.text || '') }}
                        />
                      )}
                    </div>
                  ))}
                  {isChatThinking && (
                    <div style={{ alignSelf: 'flex-start', color: '#94a3b8', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <RefreshCw size={12} className="spin" /> Analyzing network context...
                    </div>
                  )}
                </div>

                <form onSubmit={handleSendChatMessage} style={{ display: 'flex', gap: '10px', marginTop: '14px' }}>
                  <input
                    type="text"
                    className="search-input"
                    style={{ flex: 1 }}
                    placeholder="Ask NetWatch AI about network threats, mitigation commands..."
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                  />
                  <button type="submit" className="btn btn-primary" disabled={isChatThinking}>
                    <Send size={15} />
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              PAGE 7: OPERATIONS & CONTROL
             ══════════════════════════════════════════════════════════════════ */}
          {activeNav === 'controls' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              {/* Card 1: Sniffer Control */}
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title"><Radio size={18} color="#10b981" /> Passive Packet Sniffer</h3>
                  <span className={`badge ${status?.capture_running ? 'badge-green' : 'badge-red'}`}>
                    {status?.capture_running ? 'Running' : 'Stopped'}
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
                  AsyncScapy ring buffer capturing Ethernet, IPv4, TCP, UDP, ICMP, DNS frames directly into SQLite WAL engine.
                </p>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button className="btn btn-success" onClick={handleStartCapture}>
                    <Play size={14} /> Start Capture
                  </button>
                  <button className="btn btn-danger" onClick={handleStopCapture}>
                    <Square size={14} /> Stop Capture
                  </button>
                </div>
              </div>

              {/* Card 2: Discovery */}
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title"><Search size={18} color="#38bdf8" /> Subnet Discovery & Baseline</h3>
                  <span className="badge badge-blue">ARP Sweeper</span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
                  Discovers active hosts on {status?.subnet || 'subnet'} and matches hardware vendors against 1,280+ IEEE OUI records.
                </p>
                <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                  <button className="btn btn-secondary" onClick={handleScanSubnet} disabled={isScanning}>
                    <RefreshCw size={14} className={isScanning ? 'spin' : ''} />
                    <span>{isScanning ? 'Scanning Subnet...' : 'Scan Subnet Now'}</span>
                  </button>
                  <button className="btn btn-primary" onClick={handleTrustAllDevices}>
                    <ShieldCheck size={14} /> Trust All Devices
                  </button>
                </div>
              </div>

              {/* Card 3: Machine Learning Model */}
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title"><Bot size={18} color="#a855f7" /> Isolation Forest Model Pipeline</h3>
                  <span className={`badge ${modelStatus?.mode === 'detecting' ? 'badge-green' : 'badge-amber'}`}>
                    {modelStatus?.mode === 'detecting' ? 'ML Active' : 'Rules Only'}
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
                  Trains scikit-learn Isolation Forest on normal baseline telemetry to detect zero-day statistical anomalies.
                </p>

                {isLearning && (
                  <div style={{ marginBottom: '14px' }}>
                    <div style={{ fontSize: '12px', color: '#38bdf8', marginBottom: '6px' }}>
                      Recording normal baseline: {(baselineStatus?.progress_pct ?? 0).toFixed(0)}%
                    </div>
                    <div style={{ height: '6px', background: '#1e293b', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{ width: `${baselineStatus?.progress_pct ?? 0}%`, background: '#38bdf8', height: '100%', transition: 'width 0.3s' }} />
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '10px' }}>
                  <button
                    className="btn btn-secondary"
                    onClick={async () => {
                      setIsLearning(true);
                      await axios.post(`${API_BASE}/api/baseline/start?minutes=5`);
                      addToast('Baseline recording started (5m)', 'info');
                    }}
                    disabled={isLearning}
                  >
                    Start 5m Baseline
                  </button>
                  <button className="btn btn-primary" onClick={handleTrainModel}>
                    Train Model Now
                  </button>
                </div>
              </div>

              {/* Card 4: Database Reset */}
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title"><Database size={18} color="#ef4444" /> Data & Session Reset</h3>
                  <span className="badge badge-gray">{((status?.db_size_bytes || 0) / 1024 / 1024).toFixed(1)} MB</span>
                </div>
                <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
                  Wipe simulated packets, historical metrics, and threat alerts when moving between networks or starting clean demonstrations.
                </p>
                <button className="btn btn-danger" onClick={handleResetDatabase}>
                  <Trash2 size={14} /> Clear Telemetry & Reset Alerts
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* ── Anomaly AI Investigation Drawer Modal ──────────────────────── */}
      {selectedAnomalyForAI && (
        <div className="modal-overlay" onClick={() => setSelectedAnomalyForAI(null)}>
          <div className="modal-drawer" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Bot size={22} color="#38bdf8" />
                <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>SLM Incident Analysis</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedAnomalyForAI(null)}>
                <X size={16} />
              </button>
            </div>

            {isAiAnalyzing ? (
              <div style={{ padding: '60px 20px', textAlign: 'center', color: '#94a3b8' }}>
                <RefreshCw size={32} className="spin" style={{ margin: '0 auto 14px' }} />
                <p>Generating security assessment & remediation playbook...</p>
              </div>
            ) : aiAnalysisResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                <div style={{ background: '#111726', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="badge badge-red">{aiAnalysisResult.threat_title}</span>
                    <span style={{ fontSize: '12px', color: '#38bdf8' }}>MITRE: {aiAnalysisResult.mitre_technique}</span>
                  </div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: '#fff', marginTop: '10px' }}>
                    Source IP: {aiAnalysisResult.source_ip}
                  </div>
                  <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '6px' }}>{aiAnalysisResult.tactical_assessment}</p>
                </div>

                <div>
                  <h4 style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9', marginBottom: '8px', textTransform: 'uppercase' }}>
                    Immediate Containment Actions
                  </h4>
                  <ul style={{ paddingLeft: '20px', fontSize: '13px', color: '#cbd5e1', lineHeight: '1.7' }}>
                    {aiAnalysisResult.incident_playbook?.immediate_actions?.map((act, i) => (
                      <li key={i}>{act}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9', marginBottom: '8px', textTransform: 'uppercase' }}>
                    One-Click Firewall Rule (Windows PowerShell)
                  </h4>
                  <div className="code-box">
                    <span>{aiAnalysisResult.incident_playbook?.firewall_commands?.windows_powershell}</span>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => copyToClipboard(aiAnalysisResult.incident_playbook?.firewall_commands?.windows_powershell)}
                    >
                      <Copy size={13} />
                    </button>
                  </div>
                </div>

                <div>
                  <h4 style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9', marginBottom: '8px', textTransform: 'uppercase' }}>
                    Linux iptables Rule
                  </h4>
                  <div className="code-box">
                    <span>{aiAnalysisResult.incident_playbook?.firewall_commands?.linux_iptables}</span>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => copyToClipboard(aiAnalysisResult.incident_playbook?.firewall_commands?.linux_iptables)}
                    >
                      <Copy size={13} />
                    </button>
                  </div>
                </div>

                <div>
                  <h4 style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9', marginBottom: '8px', textTransform: 'uppercase' }}>
                    Long-Term Hardening
                  </h4>
                  <ul style={{ paddingLeft: '20px', fontSize: '13px', color: '#94a3b8', lineHeight: '1.7' }}>
                    {aiAnalysisResult.incident_playbook?.permanent_hardening?.map((hard, i) => (
                      <li key={i}>{hard}</li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <p style={{ color: '#ef4444' }}>Unable to retrieve analysis details.</p>
            )}
          </div>
        </div>
      )}

      {/* ── Toast Notifications Container ─────────────────────────────── */}
      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.type}`}>
            {t.type === 'success' && <CheckCircle2 size={16} color="#10b981" />}
            {t.type === 'error' && <AlertTriangle size={16} color="#ef4444" />}
            {t.type === 'info' && <Info size={16} color="#38bdf8" />}
            <span style={{ fontSize: '13px' }}>{t.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
