import React, { useState, useEffect, useRef } from 'react';
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

// Register Chart.js components
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

// Dynamic API Base URL from env or host
const API_BASE = import.meta.env.VITE_API_URL || `http://${window.location.hostname || 'localhost'}:8000`;

function formatBps(bps) {
  if (!bps || bps <= 0) return '0 bps';
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bps)} bps`;
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(2)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function formatTime(ts) {
  if (!ts) return '--:--:--';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function App() {
  const [status, setStatus] = useState(null);
  const [traffic, setTraffic] = useState([]);
  const [protocols, setProtocols] = useState(null);
  const [devices, setDevices] = useState([]);
  const [topTalkers, setTopTalkers] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [health, setHealth] = useState(null);
  const [forecast, setForecast] = useState([]);
  const [isApiOnline, setIsApiOnline] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchAllData = async () => {
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
        axios.get(`${API_BASE}/api/status`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/traffic?minutes=15`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/protocols?minutes=5`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/devices`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/top-talkers?minutes=5&limit=10`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/alerts?limit=30`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/health`, { timeout: 2500 }),
        axios.get(`${API_BASE}/api/forecast`, { timeout: 2500 }).catch(() => ({ data: { points: [] } })),
      ]);

      setStatus(statusRes.data);
      setTraffic(trafficRes.data.points || []);
      setProtocols(protoRes.data);
      setDevices(devRes.data || []);
      setTopTalkers(talkerRes.data || []);
      setAlerts(alertsRes.data || []);
      setHealth(healthRes.data);
      setForecast(forecastRes.data?.points || []);

      setIsApiOnline(true);
      setErrorMessage('');
      setLastUpdated(new Date());
    } catch (err) {
      setIsApiOnline(false);
      setErrorMessage(`Cannot connect to NetWatch API at ${API_BASE}. Make sure the backend is running.`);
    }
  };

  useEffect(() => {
    fetchAllData();
    const timer = setInterval(fetchAllData, 3000);
    return () => clearInterval(timer);
  }, []);

  const handleToggleKnown = async (mac) => {
    try {
      await axios.post(`${API_BASE}/api/devices/${encodeURIComponent(mac)}/known`);
      // Optimistic update
      setDevices((prev) =>
        prev.map((d) => (d.mac.toLowerCase() === mac.toLowerCase() ? { ...d, is_known: d.is_known === 1 ? 0 : 1 } : d))
      );
    } catch (err) {
      alert(`Failed to toggle known status: ${err.message}`);
    }
  };

  const handleAcknowledgeAlert = async (id) => {
    try {
      await axios.post(`${API_BASE}/api/alerts/${id}/ack`);
      setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, acknowledged: 1 } : a)));
    } catch (err) {
      alert(`Failed to acknowledge alert: ${err.message}`);
    }
  };

  // Derive summary metrics
  const activeDeviceCount = devices.filter((d) => d.status === 'online').length;
  const latestTraffic = traffic.length > 0 ? traffic[traffic.length - 1] : null;
  const currentTotalThroughput = latestTraffic ? latestTraffic.bps_in + latestTraffic.bps_out : 0;
  const currentLatency = latestTraffic?.latency_ms !== null && latestTraffic?.latency_ms !== undefined ? latestTraffic.latency_ms : null;
  const healthScore = health?.score ?? 100;
  const healthLabel = (health?.label || 'Healthy').toLowerCase();

  // Prepare Bandwidth Line Chart data with Forecast
  const trafficLabels = traffic.map((p) => formatTime(p.ts));
  const forecastLabels = forecast.map((p) => formatTime(p.ts));
  const allLabels = [...trafficLabels, ...forecastLabels];

  const inData = [...traffic.map((p) => p.bps_in), ...Array(forecast.length).fill(null)];
  const outData = [...traffic.map((p) => p.bps_out), ...Array(forecast.length).fill(null)];

  // Connect forecast line smoothly from last historical point
  const lastPointTotalBps = latestTraffic ? latestTraffic.bps_in + latestTraffic.bps_out : null;
  const forecastData =
    forecast.length > 0
      ? [
          ...Array(Math.max(0, traffic.length - 1)).fill(null),
          lastPointTotalBps,
          ...forecast.map((p) => p.predicted_bps),
        ]
      : [];

  const lineChartData = {
    labels: allLabels,
    datasets: [
      {
        label: 'Inbound (bps)',
        data: inData,
        borderColor: '#3fb950',
        backgroundColor: 'rgba(63, 185, 80, 0.1)',
        borderWidth: 2,
        tension: 0.2,
        pointRadius: 0,
        fill: true,
      },
      {
        label: 'Outbound (bps)',
        data: outData,
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88, 166, 255, 0.1)',
        borderWidth: 2,
        tension: 0.2,
        pointRadius: 0,
        fill: true,
      },
      ...(forecast.length > 0
        ? [
            {
              label: 'Forecast (5m)',
              data: forecastData,
              borderColor: '#f0883e',
              borderDash: [5, 5],
              borderWidth: 2,
              tension: 0.2,
              pointRadius: 0,
              fill: false,
            },
          ]
        : []),
    ],
  };

  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: {
        position: 'top',
        labels: { color: '#8b949e', boxWidth: 12, font: { size: 11 } },
      },
      tooltip: {
        backgroundColor: '#161b22',
        titleColor: '#f0f6fc',
        bodyColor: '#c9d1d9',
        borderColor: '#30363d',
        borderWidth: 1,
        callbacks: {
          label: (context) => `${context.dataset.label}: ${formatBps(context.parsed.y)}`,
        },
      },
    },
    scales: {
      x: {
        grid: { color: '#21262d' },
        ticks: { color: '#8b949e', maxTicksLimit: 8, font: { size: 10 } },
      },
      y: {
        grid: { color: '#21262d' },
        ticks: {
          color: '#8b949e',
          font: { size: 10 },
          callback: (value) => formatBps(value),
        },
      },
    },
  };

  // Prepare Doughnut Chart data
  const doughnutData = {
    labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'Other'],
    datasets: [
      {
        data: protocols
          ? [protocols.tcp, protocols.udp, protocols.icmp, protocols.dns, protocols.other]
          : [0, 0, 0, 0, 0],
        backgroundColor: ['#58a6ff', '#3fb950', '#f85149', '#d29922', '#8b949e'],
        borderWidth: 2,
        borderColor: '#161b22',
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#8b949e', boxWidth: 10, font: { size: 11 } },
      },
      tooltip: {
        backgroundColor: '#161b22',
        titleColor: '#f0f6fc',
        bodyColor: '#c9d1d9',
        borderColor: '#30363d',
        borderWidth: 1,
      },
    },
    cutout: '68%',
  };

  return (
    <div className="app-container">
      {/* API Offline Banner */}
      {!isApiOnline && (
        <div className="error-banner">
          <span>⚠️ {errorMessage}</span>
          <button className="btn btn-sm" onClick={fetchAllData}>Retry</button>
        </div>
      )}

      {/* Top Bar */}
      <header className="topbar">
        <div className="brand">
          <span className="brand-title">NETWATCH</span>
          <span className="mono" style={{ color: '#8b949e', fontSize: '12px' }}>AI Network Monitoring</span>
        </div>
        <div className="topbar-meta">
          <div className="status-indicator">
            <span className={`dot ${status?.capture_running ? 'green' : 'red'}`} />
            <span>{status?.capture_running ? 'Capturing Live' : 'Sniffer Offline'}</span>
          </div>
          <div>
            <span style={{ color: '#8b949e' }}>Interface: </span>
            <span className="mono" style={{ color: '#f0f6fc' }}>{status?.interface || '--'}</span>
          </div>
          <div>
            <span style={{ color: '#8b949e' }}>Subnet: </span>
            <span className="mono" style={{ color: '#f0f6fc' }}>{status?.subnet || '--'}</span>
          </div>
          <div>
            <span className={`health-pill ${healthLabel}`}>
              {healthScore.toFixed(0)}% {health?.label || 'Healthy'}
            </span>
          </div>
        </div>
      </header>

      {/* 4 Stat Cards */}
      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Connected Hosts</div>
          <div className="stat-value">{activeDeviceCount} <span style={{ fontSize: '14px', color: '#8b949e' }}>/ {devices.length}</span></div>
          <div className="stat-sub">{devices.filter((d) => d.is_known === 0).length} unknown devices</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Throughput (In / Out)</div>
          <div className="stat-value">{formatBps(currentTotalThroughput)}</div>
          <div className="stat-sub">
            ↓ {formatBps(latestTraffic?.bps_in || 0)} &nbsp; ↑ {formatBps(latestTraffic?.bps_out || 0)}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Gateway Latency</div>
          <div className="stat-value">
            {currentLatency !== null ? `${currentLatency.toFixed(1)} ms` : '--'}
          </div>
          <div className="stat-sub">
            Loss: {latestTraffic?.loss_pct !== null && latestTraffic?.loss_pct !== undefined ? `${latestTraffic.loss_pct.toFixed(1)}%` : '0%'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Network Health</div>
          <div className={`stat-value health-${healthLabel}`}>{healthScore.toFixed(1)}</div>
          <div className="stat-sub">
            {alerts.filter((a) => a.acknowledged === 0).length} active unresolved alerts
          </div>
        </div>
      </section>

      {/* Charts Grid */}
      <section className="charts-grid">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Bandwidth Throughput & Forecast</span>
            <span className="mono" style={{ fontSize: '11px', color: '#8b949e' }}>15m History + 5m Forecast</span>
          </div>
          <div className="chart-wrapper">
            <Line data={lineChartData} options={lineChartOptions} />
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Protocol Share</span>
            <span className="mono" style={{ fontSize: '11px', color: '#8b949e' }}>5m Window</span>
          </div>
          <div className="doughnut-wrapper">
            <Doughnut data={doughnutData} options={doughnutOptions} />
          </div>
        </div>
      </section>

      {/* Tables Grid */}
      <section className="tables-grid">
        {/* Device Inventory */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Discovered Devices ({devices.length})</span>
          </div>
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>MAC</th>
                  <th>Vendor</th>
                  <th>Hostname</th>
                  <th>Status</th>
                  <th>Whitelist</th>
                </tr>
              </thead>
              <tbody>
                {devices.length === 0 ? (
                  <tr><td colSpan="6" style={{ textAlign: 'center', color: '#8b949e' }}>No devices discovered yet.</td></tr>
                ) : (
                  devices.map((dev) => (
                    <tr key={dev.mac}>
                      <td className="mono">{dev.ip || '--'}</td>
                      <td className="mono" style={{ color: '#8b949e' }}>{dev.mac}</td>
                      <td>{dev.vendor || 'Unknown'}</td>
                      <td>{dev.hostname || '--'}</td>
                      <td>
                        <span className={`badge ${dev.status === 'online' ? 'online' : 'offline'}`}>
                          {dev.status}
                        </span>
                      </td>
                      <td>
                        <button
                          className={`btn btn-sm ${dev.is_known === 1 ? 'btn-known' : ''}`}
                          onClick={() => handleToggleKnown(dev.mac)}
                        >
                          {dev.is_known === 1 ? 'Known' : 'Mark Known'}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Talkers */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Top Talkers (Bandwidth)</span>
          </div>
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Upload</th>
                  <th>Download</th>
                  <th>Total</th>
                  <th>PPS</th>
                </tr>
              </thead>
              <tbody>
                {topTalkers.length === 0 ? (
                  <tr><td colSpan="5" style={{ textAlign: 'center', color: '#8b949e' }}>No host activity recorded.</td></tr>
                ) : (
                  topTalkers.map((t) => (
                    <tr key={t.ip}>
                      <td>
                        <div className="mono">{t.ip}</div>
                        {t.hostname && <div style={{ fontSize: '11px', color: '#8b949e' }}>{t.hostname}</div>}
                      </td>
                      <td className="mono">{formatBytes(t.bytes_out)}</td>
                      <td className="mono">{formatBytes(t.bytes_in)}</td>
                      <td className="mono" style={{ fontWeight: 600, color: '#f0f6fc' }}>{formatBytes(t.total_bytes)}</td>
                      <td className="mono">{t.avg_pps.toFixed(1)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Alert List */}
      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">AI Anomaly & Threat Alerts ({alerts.filter((a) => a.acknowledged === 0).length} Unresolved)</span>
        </div>
        <div className="alert-list">
          {alerts.length === 0 ? (
            <div style={{ color: '#8b949e', textAlign: 'center', padding: '20px 0' }}>
              No active alerts detected. Traffic is clean.
            </div>
          ) : (
            alerts.map((alert) => (
              <div
                key={alert.id}
                className={`alert-item ${alert.severity}`}
                style={{ opacity: alert.acknowledged === 1 ? 0.45 : 1 }}
              >
                <div className="alert-main">
                  <div className="alert-top">
                    <span className={`badge ${alert.severity}`}>{alert.severity.toUpperCase()}</span>
                    <span className="mono" style={{ color: '#8b949e', fontSize: '11px' }}>{alert.alert_type}</span>
                    <span className="alert-time">{formatTime(alert.ts)}</span>
                    <span className="mono" style={{ color: '#8b949e', fontSize: '11px' }}>Score: {alert.score.toFixed(2)}</span>
                  </div>
                  <div className="alert-msg">{alert.message}</div>
                </div>
                <div>
                  {alert.acknowledged === 1 ? (
                    <span style={{ fontSize: '11px', color: '#8b949e' }}>Acknowledged</span>
                  ) : (
                    <button className="btn btn-sm" onClick={() => handleAcknowledgeAlert(alert.id)}>
                      Acknowledge
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
