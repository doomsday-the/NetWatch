"""FastAPI REST API server for the NetWatch dashboard.

Provides endpoints for:
- System and packet capture status
- Device inventory and whitelist management
- Real-time traffic timeseries (bps in/out, pps, latency, loss)
- Protocol distribution and top talkers
- AI anomaly alerts and acknowledgement
- Health scoring and traffic forecasting
"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Path, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.config import settings
from backend.db import (
    acknowledge_alert,
    get_ai_alerts,
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
    return SystemStatusResponse(**status_data)


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
    mac: str = Path(..., description="Target device MAC address"),
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
    alert_id: int = Path(..., alias="alert_id", description="Primary key ID of the alert"),
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
    health_data = get_health_status(limit=30)
    return HealthStatusResponse(**health_data)


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
