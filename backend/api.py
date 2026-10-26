"""FastAPI REST API server for the NetWatch dashboard.

Provides endpoints for:
- System and packet capture status
- Device inventory and whitelist management
- Real-time traffic timeseries (bps in/out, pps, latency, loss)
- Protocol distribution and top talkers
- AI anomaly alerts and acknowledgement
- Health scoring and traffic forecasting
- Control endpoints: model training, baseline recording, capture control,
  network discovery sweep, interface enumeration, and attack command generation (tags: Control)
"""

from __future__ import annotations

import argparse
import logging
import socket
import threading
import time as _time
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import uvicorn
from fastapi import FastAPI, HTTPException, Path as FPath, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.config import settings
from backend.db import (
    acknowledge_alert,
    get_ai_alerts,
    get_connection,
    get_device_inventory,
    get_health_status,
    get_protocol_distribution,
    get_system_status,
    get_top_talkers,
    get_traffic_timeseries,
    toggle_device_known,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state dict – tracks in-process background operations
# ---------------------------------------------------------------------------

_state: Dict[str, Any] = {
    "capture_active": True,          # True by default; toggled by /api/capture/start|stop
    "train_running": False,          # True while model training thread is alive
    "scan_running": False,           # True while network discovery scan thread is alive
    "baseline_running": False,       # True while baseline recording thread is alive
    "baseline_status": "idle",       # idle | running | done
    "baseline_started_at": None,     # float Unix timestamp when baseline started
    "baseline_minutes": 0.0,         # requested duration
    "baseline_windows": 0,           # placeholder for collected windows counter
    # Model metadata cache
    "_model_mtime": None,            # last seen mtime of model file
    "_model_meta": None,             # cached metadata dict from joblib artifact
}

# Initialize FastAPI application
app = FastAPI(
    title="NetWatch API",
    description="Real-time network monitoring, traffic telemetry, and AI anomaly detection API.",
    version="1.0.0",
)

# Enable Cross-Origin Resource Sharing (CORS) for all origins (React dashboard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic Response Models
# ---------------------------------------------------------------------------

class SystemStatusResponse(BaseModel):
    """Operational status of NetWatch capture services and database."""

    capture_running: bool = Field(description="True if packets have been captured recently")
    last_packet_time: Optional[float] = Field(description="Unix epoch timestamp of most recent captured packet")
    db_size_bytes: int = Field(description="Total disk footprint of SQLite DB and WAL files in bytes")
    interface: str = Field(description="Active capture network interface")
    subnet: str = Field(description="Monitored LAN subnet in CIDR notation")
    gateway: Optional[str] = Field(description="Default gateway IP address")
    capture_active: bool = Field(
        description="True if capture has been explicitly started from the UI",
        default=True,
    )
    model_mode: str = Field(
        description="untrained / learning / detecting",
        default="untrained",
    )


class DeviceResponse(BaseModel):
    """Discovered network host in inventory."""

    mac: str = Field(description="Standard colon-delimited MAC address")
    ip: Optional[str] = Field(description="Latest observed IP address")
    vendor: Optional[str] = Field(description="Manufacturer hardware vendor from OUI lookup")
    hostname: Optional[str] = Field(description="Resolved hostname via reverse DNS or mDNS")
    status: str = Field(description="Online or offline status")
    is_known: int = Field(description="1 if marked as trusted baseline host, 0 if unknown")
    first_seen: Optional[float] = Field(description="Unix timestamp when host was first observed")
    last_seen: Optional[float] = Field(description="Unix timestamp when host was most recently seen")


class ToggleKnownResponse(BaseModel):
    """Result of toggling host whitelist/known status."""

    mac: str = Field(description="Device MAC address")
    is_known: int = Field(description="Updated is_known status (0 or 1)")
    message: str = Field(description="Informational status message")


class TrafficDataPoint(BaseModel):
    """Network-wide traffic telemetry for a discrete aggregation window."""

    ts: float = Field(description="Unix epoch timestamp of the window boundary")
    bps_in: float = Field(description="Inbound / download throughput in bits per second")
    bps_out: float = Field(description="Outbound / upload throughput in bits per second")
    bytes_in: int = Field(description="Total inbound bytes in this window")
    bytes_out: int = Field(description="Total outbound bytes in this window")
    pps: float = Field(description="Average packets per second in this window")
    latency_ms: Optional[float] = Field(description="Gateway ping round-trip time in milliseconds")
    loss_pct: Optional[float] = Field(description="Gateway probe packet loss percentage")


class TrafficSeriesResponse(BaseModel):
    """Chronological traffic metrics time series."""

    minutes: float = Field(description="Time window duration in minutes")
    points: List[TrafficDataPoint] = Field(description="Chronologically sorted traffic metric data points")


class ProtocolShareResponse(BaseModel):
    """Protocol distribution counts."""

    minutes: float = Field(description="Duration in minutes analyzed")
    total_packets: int = Field(description="Total packet volume in window")
    tcp: int = Field(description="TCP packet count")
    udp: int = Field(description="UDP packet count")
    icmp: int = Field(description="ICMP packet count")
    dns: int = Field(description="DNS packet count (port 53)")
    other: int = Field(description="Other protocols packet count")


class TopTalkerResponse(BaseModel):
    """Host consumption summary."""

    ip: str = Field(description="Host IP address")
    bytes_out: int = Field(description="Total bytes transmitted by host")
    bytes_in: int = Field(description="Total bytes received by host")
    total_bytes: int = Field(description="Combined upload and download byte total")
    avg_pps: float = Field(description="Average packets per second")
    hostname: Optional[str] = Field(description="Host domain name or hostname")
    vendor: Optional[str] = Field(description="Hardware vendor")
    status: Optional[str] = Field(description="Host current status (online/offline)")
    is_known: int = Field(description="Known whitelist flag (0 or 1)")


class AlertResponse(BaseModel):
    """AI network anomaly alert record."""

    id: int = Field(description="Unique alert record primary key")
    ts: float = Field(description="Unix timestamp when alert was generated")
    alert_type: str = Field(description="Alert category (e.g. unknown_device, syn_flood, high_volume)")
    severity: str = Field(description="Severity rating: info, low, medium, warning, critical")
    src_ip: Optional[str] = Field(description="Source IP triggering the alert")
    message: str = Field(description="Human-readable summary of the detected anomaly")
    score: float = Field(description="Anomaly confidence score (0.0 - 1.0)")
    acknowledged: int = Field(description="1 if dismissed/acknowledged by operator, 0 if pending")
    details_json: Optional[str] = Field(description="Serialized JSON dictionary with extra context")


class AckResponse(BaseModel):
    """Acknowledgement status."""

    id: int = Field(description="Alert ID")
    acknowledged: bool = Field(description="True if successfully marked as acknowledged")
    message: str = Field(description="Confirmation message")


class HealthHistoryPoint(BaseModel):
    """Historical health score entry."""

    id: int = Field(description="Primary key")
    ts: float = Field(description="Unix timestamp")
    score: float = Field(description="Network health score (0 - 100)")


class HealthStatusResponse(BaseModel):
    """Current overall health evaluation."""

    score: float = Field(description="Latest evaluated health score (0.0 to 100.0)")
    label: str = Field(description="Health categorization: Healthy, Degraded, or Critical")
    last_updated: float = Field(description="Unix timestamp of latest evaluation")
    history: List[Dict[str, Any]] = Field(description="Historical trend data points for chart display")


class ForecastPoint(BaseModel):
    """Predicted future bandwidth consumption."""

    ts: float = Field(description="Target future Unix epoch timestamp")
    predicted_bps: float = Field(description="Predicted bandwidth in bits per second")
    confidence_lower_bps: Optional[float] = Field(description="Lower bound confidence interval")
    confidence_upper_bps: Optional[float] = Field(description="Upper bound confidence interval")


class ForecastResponse(BaseModel):
    """Bandwidth forecasting prediction response."""

    points: List[ForecastPoint] = Field(description="Projected bandwidth data points")
    model_loaded: bool = Field(description="True if ML forecast model is active")
    message: str = Field(description="Status message")


# ---------------------------------------------------------------------------
# Control Endpoint – Pydantic Response Models
# ---------------------------------------------------------------------------

class ModelStatusResponse(BaseModel):
    """Training state of the anomaly-detection ML model."""

    trained: bool = Field(description="True if a trained model artifact exists on disk")
    trained_at: Optional[float] = Field(description="Unix timestamp when model was last trained")
    sample_count: Optional[int] = Field(description="Number of samples used during training")
    mode: str = Field(description="Operational mode: untrained | learning | detecting")


class TrainResponse(BaseModel):
    """Response from a model training trigger request."""

    status: str = Field(description="started | already_running | error")
    message: str = Field(description="Human-readable detail message")


class BaselineStartResponse(BaseModel):
    """Response from a baseline recording start request."""

    status: str = Field(description="started | already_running | error")
    message: str = Field(description="Human-readable detail message")


class BaselineStatusResponse(BaseModel):
    """Real-time progress of an ongoing or completed baseline recording."""

    running: bool = Field(description="True if baseline recording is currently active")
    status: str = Field(default="idle", description="Current status: idle | running | done")
    progress_pct: float = Field(description="Completion percentage (0.0 – 100.0)")
    windows_collected: int = Field(description="Approximate number of aggregation windows captured")
    minutes: float = Field(description="Total requested recording duration in minutes")
    started_at: Optional[float] = Field(description="Unix timestamp when recording began")


class ScanResponse(BaseModel):
    """Response from a network discovery scan request."""

    status: str = Field(description="success | started | already_running | error")
    message: str = Field(description="Human-readable detail message")
    count: Optional[int] = Field(default=None, description="Number of active online devices")
    devices: Optional[List[Dict[str, Any]]] = Field(default=None, description="List of active devices")


class CaptureControlResponse(BaseModel):
    """Response from a capture start/stop control request."""

    status: str = Field(description="ok | error")
    message: str = Field(description="Human-readable detail message")


class InterfaceListResponse(BaseModel):
    """Available network interfaces on this host."""

    interfaces: List[str] = Field(description="List of network interface names detected by psutil")


class AttackCommand(BaseModel):
    """A ready-to-run Kali Linux attack command for testing NetWatch detection."""

    name: str = Field(description="Short identifier for the attack type")
    command: str = Field(description="Full shell command pre-filled with detected host IP")
    expected_alert: str = Field(description="Alert type NetWatch should raise when this runs")
    description: str = Field(description="Brief explanation of what the command does")


class AttackCommandsResponse(BaseModel):
    """Collection of test attack commands targeting this host."""

    target_ip: str = Field(description="Detected IP address used in the generated commands")
    commands: List[AttackCommand] = Field(description="Ready-to-run attack commands")


# ---------------------------------------------------------------------------
# Model Metadata Helper
# ---------------------------------------------------------------------------

def _get_model_metadata() -> Dict[str, Any]:
    """Return cached model metadata dict, refreshing only when file mtime changes.

    Loads the joblib artifact from ``settings.model_path`` and caches both the
    metadata and the file modification time so subsequent calls do not incur
    disk I/O unless the file has been updated.

    Returns:
        A dict with keys ``trained`` (bool), ``trained_at`` (float | None),
        ``sample_count`` (int | None), and ``mode`` (str).
    """
    model_path = Path(settings.model_path)
    if not model_path.exists():
        return {"trained": False, "trained_at": None, "sample_count": None, "mode": "untrained"}

    try:
        current_mtime = model_path.stat().st_mtime
    except OSError:
        return {"trained": False, "trained_at": None, "sample_count": None, "mode": "untrained"}

    if _state.get("_model_mtime") == current_mtime and _state.get("_model_meta") is not None:
        return _state["_model_meta"]

    # Load artifact and cache
    try:
        import joblib  # type: ignore

        artifact = joblib.load(model_path)
        trained_at = artifact.get("trained_at") if isinstance(artifact, dict) else None
        sample_count = artifact.get("sample_count") if isinstance(artifact, dict) else None
        mode = "detecting"
        meta = {
            "trained": True,
            "trained_at": trained_at,
            "sample_count": sample_count,
            "mode": mode,
        }
    except Exception:
        meta = {"trained": True, "trained_at": None, "sample_count": None, "mode": "detecting"}

    _state["_model_mtime"] = current_mtime
    _state["_model_meta"] = meta
    _state["model_mode"] = meta["mode"]
    return meta


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get(
    "/api/status",
    response_model=SystemStatusResponse,
    summary="Get System and Capture Status",
    tags=["System"],
)
def get_status() -> SystemStatusResponse:
    """Retrieve operational telemetry about packet sniffer, database footprint, and network interfaces."""
    status_data = get_system_status()
    meta = _get_model_metadata()
    model_mode = meta.get("mode", "untrained")
    return SystemStatusResponse(
        **status_data,
        capture_active=_state.get("capture_active", True),
        model_mode=model_mode,
    )


@app.get(
    "/api/devices",
    response_model=List[DeviceResponse],
    summary="List Discovered Devices",
    tags=["Inventory"],
)
def list_devices(
    only_active: bool = Query(False, description="Filter for devices seen within active window"),
) -> List[DeviceResponse]:
    """Retrieve complete inventory of discovered network hosts including vendor and online status."""
    devices = get_device_inventory(only_active=only_active)
    return [DeviceResponse(**d) for d in devices]


@app.post(
    "/api/devices/{mac}/known",
    response_model=ToggleKnownResponse,
    summary="Toggle Device Known Status",
    tags=["Inventory"],
)
def toggle_device(
    mac: str = FPath(..., description="Target device MAC address"),
) -> ToggleKnownResponse:
    """Toggle is_known status for a device between 0 (unknown/untrusted) and 1 (known/trusted)."""
    new_val = toggle_device_known(mac)
    if new_val is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with MAC '{mac}' not found in inventory",
        )
    label = "known / trusted" if new_val == 1 else "unknown / untrusted"
    return ToggleKnownResponse(
        mac=mac,
        is_known=new_val,
        message=f"Device '{mac}' marked as {label}",
    )


@app.get(
    "/api/traffic",
    response_model=TrafficSeriesResponse,
    summary="Get Network Traffic Timeseries",
    tags=["Telemetry"],
)
def get_traffic(
    minutes: float = Query(15.0, ge=1.0, le=1440.0, description="Lookback window in minutes"),
) -> TrafficSeriesResponse:
    """Fetch chronological network-wide throughput (bps in/out, pps, latency, and packet loss)."""
    points_data = get_traffic_timeseries(
        minutes=minutes,
        window_seconds=settings.agg_window_seconds,
    )
    points = [TrafficDataPoint(**p) for p in points_data]
    return TrafficSeriesResponse(minutes=minutes, points=points)


@app.get(
    "/api/protocols",
    response_model=ProtocolShareResponse,
    summary="Get Protocol Share Distribution",
    tags=["Telemetry"],
)
def get_protocols(
    minutes: float = Query(5.0, ge=1.0, le=1440.0, description="Duration in minutes"),
) -> ProtocolShareResponse:
    """Retrieve breakdown of packet volume by protocol (TCP, UDP, ICMP, DNS, OTHER)."""
    proto_data = get_protocol_distribution(minutes=minutes)
    return ProtocolShareResponse(**proto_data)


@app.get(
    "/api/top-talkers",
    response_model=List[TopTalkerResponse],
    summary="Get Top Talkers by Bandwidth",
    tags=["Telemetry"],
)
def get_talkers(
    minutes: float = Query(5.0, ge=1.0, le=1440.0, description="Lookback window in minutes"),
    limit: int = Query(10, ge=1, le=100, description="Maximum hosts to return"),
) -> List[TopTalkerResponse]:
    """Retrieve highest bandwidth consuming hosts in the network over the specified time period."""
    talkers_data = get_top_talkers(minutes=minutes, limit=limit)
    return [TopTalkerResponse(**t) for t in talkers_data]


@app.get(
    "/api/alerts",
    response_model=List[AlertResponse],
    summary="List AI Anomaly Alerts",
    tags=["Alerts"],
)
def list_alerts(
    limit: int = Query(50, ge=1, le=500, description="Maximum alerts to retrieve"),
    severity: Optional[str] = Query(None, description="Optional severity filter (e.g. medium, critical)"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged status"),
) -> List[AlertResponse]:
    """Retrieve AI anomaly alerts sorted newest first."""
    alerts_data = get_ai_alerts(
        limit=limit,
        acknowledged=acknowledged,
        severity=severity,
    )
    return [AlertResponse(**a) for a in alerts_data]


@app.post(
    "/api/alerts/{alert_id}/ack",
    response_model=AckResponse,
    summary="Acknowledge Alert",
    tags=["Alerts"],
)
def ack_alert(
    alert_id: int = FPath(..., alias="alert_id", description="Primary key ID of the alert"),
) -> AckResponse:
    """Mark an alert as acknowledged / dismissed."""
    success = acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    return AckResponse(
        id=alert_id,
        acknowledged=True,
        message=f"Alert {alert_id} acknowledged successfully",
    )


@app.get(
    "/api/health",
    response_model=HealthStatusResponse,
    summary="Get Network Health Score & History",
    tags=["Health"],
)
def get_health() -> HealthStatusResponse:
    """Retrieve the latest network health evaluation score, categorical label, and history."""
    from backend.db import get_health_status
    data = get_health_status(limit=30)
    return HealthStatusResponse(
        score=data["score"],
        label=data["label"],
        last_updated=data["last_updated"],
        history=data.get("history", []),
    )


@app.get(
    "/api/forecast",
    response_model=ForecastResponse,
    summary="Get Bandwidth Forecast",
    tags=["Forecasting"],
)
def get_forecast() -> ForecastResponse:
    """Retrieve predicted bandwidth requirements for the upcoming 5 minutes.

    Returns an empty points list when the machine learning forecasting module is offline or uninitialized.
    """
    # Check if forecasting module exists and has trained weights
    forecast_points: List[ForecastPoint] = []
    try:
        from backend.ml.forecast import generate_bandwidth_forecast  # type: ignore

        raw_points = generate_bandwidth_forecast(horizon_minutes=5.0)
        forecast_points = [ForecastPoint(**p) for p in raw_points]
        return ForecastResponse(
            points=forecast_points,
            model_loaded=True,
            message="Active forecasting model predictions",
        )
    except (ImportError, AttributeError, Exception):
        # Fall back to empty list until backend/ml/forecast.py is trained
        return ForecastResponse(
            points=[],
            model_loaded=False,
            message="Forecasting model is uninitialized or offline",
        )


# ---------------------------------------------------------------------------
# Control Endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/api/model/status",
    response_model=ModelStatusResponse,
    summary="Get ML Model Status",
    tags=["Control"],
)
def get_model_status() -> ModelStatusResponse:
    """Return the current training state of the anomaly-detection ML model.

    Reads model artifact metadata from disk (with mtime-based caching) to
    report whether a trained model exists, when it was trained, how many
    samples were used, and the current operational mode
    (``untrained`` | ``learning`` | ``detecting``).
    """
    meta = _get_model_metadata()
    return ModelStatusResponse(**meta)


def _run_train_in_background() -> None:
    """Background thread target: invoke train_model() and update _state flags."""
    _state["train_running"] = True
    _state["model_mode"] = "learning"
    try:
        from backend.ml.train import train_model  # type: ignore

        train_model()
        logger.info("Model training completed successfully.")
    except Exception as exc:
        logger.exception("Model training failed: %s", exc)
    finally:
        _state["train_running"] = False
        # Invalidate metadata cache so next status call re-reads from disk
        _state["_model_mtime"] = None
        _state["_model_meta"] = None
        # Re-derive mode from freshly written artifact
        _get_model_metadata()


@app.post(
    "/api/model/train",
    response_model=TrainResponse,
    summary="Trigger ML Model Training",
    tags=["Control"],
)
def trigger_train() -> TrainResponse:
    """Start a background model training run using the current baseline dataset.

    If a training job is already in progress the call returns immediately with
    ``status="already_running"`` and does not spawn an additional thread.
    Training is executed via ``train_model()`` from ``backend.ml.train`` in a
    daemon background thread so it does not block the API event loop.
    """
    if _state.get("train_running"):
        return TrainResponse(status="already_running", message="A training job is already in progress.")
    try:
        thread = threading.Thread(target=_run_train_in_background, daemon=True, name="netwatch-train")
        thread.start()
        return TrainResponse(status="started", message="Model training started in the background.")
    except Exception as exc:
        logger.exception("Failed to start training thread: %s", exc)
        return TrainResponse(status="error", message=f"Failed to start training thread: {exc}")


def _run_baseline_in_background(duration_seconds: float, started_at: float) -> None:
    """Background thread target: wait for the baseline duration then persist metadata to DB.

    Args:
        duration_seconds: Total number of seconds to record the baseline for.
        started_at: Unix timestamp when the recording was initiated.
    """
    _state["baseline_running"] = True
    _state["baseline_status"] = "running"
    try:
        _time.sleep(duration_seconds)
        end_ts = _time.time()
        # Persist baseline metadata to SQLite using standard helper
        from backend.db import save_baseline_metadata
        save_baseline_metadata(
            start_ts=started_at,
            end_ts=end_ts,
            name="web_baseline",
        )
        logger.info("Baseline recording complete. Metadata written to DB.")
    except Exception as exc:
        logger.exception("Baseline background thread error: %s", exc)
    finally:
        _state["baseline_running"] = False
        _state["baseline_status"] = "done"


@app.post(
    "/api/baseline/start",
    response_model=BaselineStartResponse,
    summary="Start Baseline Traffic Recording",
    tags=["Control"],
)
def start_baseline(
    minutes: float = Query(5.0, ge=0.1, le=60.0, description="Recording duration in minutes"),
) -> BaselineStartResponse:
    """Begin a timed baseline traffic recording session.

    Records the current timestamp and schedules a background thread to mark
    the end of the recording in the ``baseline_metadata`` SQLite table after
    the requested number of minutes.  If a baseline session is already
    running the request is rejected with ``status="already_running"``.
    """
    if _state.get("baseline_running"):
        return BaselineStartResponse(
            status="already_running",
            message="A baseline recording session is already in progress.",
        )
    try:
        started_at = _time.time()
        _state["baseline_started_at"] = started_at
        _state["baseline_minutes"] = minutes
        _state["baseline_windows"] = 0
        _state["baseline_status"] = "running"
        duration_seconds = minutes * 60.0
        thread = threading.Thread(
            target=_run_baseline_in_background,
            args=(duration_seconds, started_at),
            daemon=True,
            name="netwatch-baseline",
        )
        thread.start()
        return BaselineStartResponse(
            status="started",
            message=f"Baseline recording started for {minutes:.1f} minute(s).",
        )
    except Exception as exc:
        logger.exception("Failed to start baseline thread: %s", exc)
        return BaselineStartResponse(status="error", message=f"Failed to start baseline: {exc}")


@app.get(
    "/api/baseline/status",
    response_model=BaselineStatusResponse,
    summary="Get Baseline Recording Status",
    tags=["Control"],
)
def get_baseline_status() -> BaselineStatusResponse:
    """Return real-time progress of the current (or most recent) baseline recording session.

    ``progress_pct`` is computed from elapsed time vs total requested duration.
    ``windows_collected`` reflects the counter maintained by the baseline thread
    (approximate; updated at best-effort intervals).
    """
    running = bool(_state.get("baseline_running"))
    started_at: Optional[float] = _state.get("baseline_started_at")
    minutes: float = float(_state.get("baseline_minutes", 0.0))
    windows: int = int(_state.get("baseline_windows", 0))

    if started_at is None or minutes == 0.0:
        progress_pct = 0.0
    else:
        elapsed = _time.time() - started_at
        total = minutes * 60.0
        progress_pct = min(100.0, (elapsed / total) * 100.0) if total > 0 else 100.0

    b_status = _state.get("baseline_status", "idle")
    if running:
        b_status = "running"
    elif started_at is not None and progress_pct >= 100.0:
        b_status = "done"

    return BaselineStatusResponse(
        running=running,
        status=b_status,
        progress_pct=round(progress_pct, 2),
        windows_collected=windows,
        minutes=minutes,
        started_at=started_at,
    )


def _run_discovery_sweep_in_background() -> None:
    """Background thread target: invoke run_discovery_sweep()."""
    _state["scan_running"] = True
    try:
        from backend.discovery import run_discovery_sweep

        run_discovery_sweep()
        logger.info("On-demand network discovery sweep completed successfully.")
    except Exception as exc:
        logger.exception("On-demand network discovery sweep failed: %s", exc)
    finally:
        _state["scan_running"] = False


@app.post(
    "/api/discovery/scan",
    response_model=ScanResponse,
    summary="Trigger On-Demand Network Discovery Sweep",
    tags=["Control"],
)
def trigger_scan(wait: bool = Query(True, description="Synchronously wait and return fresh devices")) -> ScanResponse:
    """Start an on-demand network ARP discovery sweep.

    If wait=True (default), executes synchronously and returns fresh device inventory immediately.
    """
    from backend.discovery import run_discovery_sweep
    from backend.db import get_device_inventory

    if wait:
        try:
            summary = run_discovery_sweep()
            devices = get_device_inventory()
            online_count = sum(1 for d in devices if d.get("status") == "online")
            return ScanResponse(
                status="success",
                message=f"Network scan completed. Discovered {online_count} active devices.",
                count=online_count,
                devices=devices,
            )
        except Exception as exc:
            logger.exception("On-demand network discovery sweep failed: %s", exc)
            return ScanResponse(status="error", message=f"Discovery sweep failed: {exc}")

    if _state.get("scan_running"):
        return ScanResponse(
            status="already_running",
            message="A network discovery scan is already in progress.",
        )
    try:
        thread = threading.Thread(
            target=_run_discovery_sweep_in_background,
            daemon=True,
            name="netwatch-discovery-scan",
        )
        thread.start()
        return ScanResponse(status="started", message="Network discovery scan started in background.")
    except Exception as exc:
        logger.exception("Failed to start network discovery sweep thread: %s", exc)
        return ScanResponse(status="error", message=f"Failed to start discovery sweep: {exc}")


@app.post(
    "/api/capture/start",
    response_model=CaptureControlResponse,
    summary="Mark Capture as Active",
    tags=["Control"],
)
def start_capture() -> CaptureControlResponse:
    """Record user intent to have packet capture active.

    The actual capture workers are started by ``run_all.py`` at process
    startup.  This endpoint merely sets ``_state["capture_active"] = True``
    so that the UI can reflect the operator's explicit intent.
    """
    _state["capture_active"] = True
    return CaptureControlResponse(status="ok", message="Capture marked as active.")


@app.post(
    "/api/capture/stop",
    response_model=CaptureControlResponse,
    summary="Mark Capture as Inactive",
    tags=["Control"],
)
def stop_capture() -> CaptureControlResponse:
    """Record user intent to pause packet capture.

    Sets ``_state["capture_active"] = False``.  The underlying workers
    continue running at the process level; this flag is reflected in
    ``/api/status`` for the dashboard to display appropriate UI state.
    """
    _state["capture_active"] = False
    return CaptureControlResponse(status="ok", message="Capture marked as inactive.")


@app.get(
    "/api/interfaces",
    response_model=InterfaceListResponse,
    summary="List Network Interfaces",
    tags=["Control"],
)
def list_interfaces() -> InterfaceListResponse:
    """Return all network interface names visible to this host via psutil.

    Uses ``psutil.net_if_stats()`` which returns all interfaces regardless
    of their current up/down state.
    """
    iface_names = sorted(psutil.net_if_stats().keys())
    return InterfaceListResponse(interfaces=iface_names)


def _get_local_ip() -> str:
    """Resolve the primary outbound IP address of this machine.

    Prefers ``settings.resolved_ip`` when available; falls back to a
    ``socket.gethostbyname`` lookup against the system hostname.

    Returns:
        A dotted-decimal IPv4 address string.
    """
    resolved = getattr(settings, "resolved_ip", None)
    if resolved:
        return str(resolved)
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


@app.get(
    "/api/attack-commands",
    response_model=AttackCommandsResponse,
    summary="Get Pre-filled Attack Commands for Testing",
    tags=["Control"],
)
def get_attack_commands() -> AttackCommandsResponse:
    """Return a set of ready-to-use Kali Linux commands for validating NetWatch alert detection.

    Each command is pre-filled with the detected local IP address so it can
    be pasted directly into a Kali terminal.  The ``expected_alert`` field
    indicates which NetWatch alert type should be raised when the command runs.
    """
    target_ip = _get_local_ip()
    commands: List[AttackCommand] = [
        AttackCommand(
            name="nmap_syn_scan",
            command=f"sudo nmap -sS {target_ip}",
            expected_alert="port_scan",
            description="TCP SYN (stealth) port scan – sends SYN packets and records responses without completing handshakes.",
        ),
        AttackCommand(
            name="nmap_connect_scan",
            command=f"nmap -sT {target_ip}",
            expected_alert="port_scan",
            description="TCP connect scan – performs full three-way handshake for each probed port.",
        ),
        AttackCommand(
            name="hping3_syn_flood",
            command=f"sudo hping3 -S --flood -V -p 80 {target_ip}",
            expected_alert="syn_flood",
            description="SYN flood attack – sends a high-rate stream of TCP SYN packets to exhaust connection state.",
        ),
        AttackCommand(
            name="hping3_icmp_flood",
            command=f"sudo hping3 --icmp --flood {target_ip}",
            expected_alert="icmp_flood",
            description="ICMP flood – saturates the target with ICMP echo requests at maximum packet rate.",
        ),
        AttackCommand(
            name="iperf3_bandwidth_hog",
            command=f"iperf3 -c {target_ip} -t 60 -P 8",
            expected_alert="bandwidth_hog",
            description="iperf3 bulk-transfer test – opens 8 parallel TCP streams for 60 seconds to stress bandwidth.",
        ),
        AttackCommand(
            name="nmap_ping_sweep",
            command=f"nmap -sn {target_ip}/24",
            expected_alert="unknown_device",
            description="Ping sweep of the /24 subnet – discovers live hosts and may surface unknown devices.",
        ),
    ]
    return AttackCommandsResponse(target_ip=target_ip, commands=commands)




# ---------------------------------------------------------------------------
# Security Audits & Defensive Verification
# ---------------------------------------------------------------------------

class SecurityAuditRequest(BaseModel):
    check_type: str = Field(default="all", description="all | syn_flood | port_scan | icmp_flood | bandwidth_drain | arp_spoof | rogue_device")


@app.post(
    "/api/security/audit",
    summary="Run Defensive Security Audit",
    tags=["Security"],
)
def security_audit_endpoint(req: Optional[SecurityAuditRequest] = None) -> Dict[str, Any]:
    """Perform defensive verification against live network flows to detect active attacks."""
    from backend.security_audit import run_comprehensive_security_audit
    check_type = req.check_type if req else "all"
    return run_comprehensive_security_audit(check_type=check_type)


# ---------------------------------------------------------------------------
# SLM / AI Security Copilot
# ---------------------------------------------------------------------------

class AnomalyAnalysisRequest(BaseModel):
    alert_id: Optional[int] = None
    alert: Optional[Dict[str, Any]] = None


@app.post(
    "/api/ai/analyze",
    summary="AI SLM Anomaly Reasoning & Remediation Playbook",
    tags=["AI"],
)
def analyze_anomaly_endpoint(req: AnomalyAnalysisRequest) -> Dict[str, Any]:
    """Generate intelligent incident response playbook and fix commands for an anomaly."""
    from backend.slm_advisor import analyze_anomaly_with_slm
    from backend.db import get_ai_alerts
    alert_data = req.alert or {}
    if not alert_data and req.alert_id:
        matching = get_ai_alerts(limit=50)
        for a in matching:
            if a.get("id") == req.alert_id:
                alert_data = a
                break
    return analyze_anomaly_with_slm(alert_data)


class AIChatRequest(BaseModel):
    message: str = Field(..., description="User security query")


@app.post(
    "/api/ai/chat",
    summary="Interactive SLM Security Copilot Chat",
    tags=["AI"],
)
def ai_chat_endpoint(req: AIChatRequest) -> Dict[str, Any]:
    """Conversational security copilot analyzing real-time network posture."""
    from backend.slm_advisor import chat_with_slm
    return chat_with_slm(req.message)


# ---------------------------------------------------------------------------
# Live Packet Flows Deep Inspection
# ---------------------------------------------------------------------------

@app.get(
    "/api/flows",
    summary="Get Real-Time Packet Flows",
    tags=["Telemetry"],
)
def get_flows(
    limit: int = Query(100, ge=1, le=1000),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """Retrieve raw packet flow stream for deep network inspection."""
    from backend.db import get_recent_packet_flows
    flows = get_recent_packet_flows(limit=limit, src_ip=src_ip, dst_ip=dst_ip)
    if protocol:
        proto_clean = protocol.upper()
        flows = [f for f in flows if (f.get("protocol") or "").upper() == proto_clean]
    return flows


# ---------------------------------------------------------------------------
# Database & Baseline Controls
# ---------------------------------------------------------------------------

@app.post(
    "/api/database/reset",
    summary="Clear Database Telemetry and Stored Alerts",
    tags=["Control"],
)
def reset_database_endpoint(
    clear_devices: bool = Query(True, description="Also purge device inventory"),
) -> Dict[str, Any]:
    """Purge old/simulated packets, metrics, health history, and alerts."""
    from backend.db import reset_database_tables
    purged = reset_database_tables(clear_devices=clear_devices)
    return {"status": "ok", "message": "Database successfully reset to clean state", "deleted": purged}


@app.post(
    "/api/devices/baseline",
    summary="Mark All Discovered Devices as Known Baseline",
    tags=["Inventory"],
)
def baseline_all_devices_endpoint() -> Dict[str, Any]:
    """Mark all currently registered devices as known / trusted baseline."""
    from backend.db import baseline_all_devices
    count = baseline_all_devices()
    return {"status": "ok", "message": f"Marked {count} devices as known / trusted baseline."}

# ---------------------------------------------------------------------------
# Frontend Static Asset Hosting (Single Port 8000)
# ---------------------------------------------------------------------------

frontend_dist = settings.absolute_db_path.parent / "frontend" / "dist"
if frontend_dist.exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        """Serve built React single-page application assets and fallback to index.html."""
        if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

        target_file = frontend_dist / full_path
        if full_path and target_file.is_file():
            return FileResponse(target_file)

        index_file = frontend_dist / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Frontend build index.html not found",
        )
else:
    logger.info("Frontend dist directory not found at %s. API running in headless mode.", frontend_dist)


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------






def main() -> None:
    """Launch NetWatch FastAPI application with Uvicorn."""
    parser = argparse.ArgumentParser(description="NetWatch REST API Server")
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Bind host (default: from config, 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (default: from config, 8000)",
    )

    args = parser.parse_args()
    bind_host = args.host or settings.api_host
    bind_port = args.port or settings.api_port

    logger.info("Starting NetWatch REST API server on %s:%d...", bind_host, bind_port)
    uvicorn.run(
        "backend.api:app",
        host=bind_host,
        port=bind_port,
        reload=False,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
