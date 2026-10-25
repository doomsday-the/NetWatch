"""Configuration management for NetWatch.

Centralizes all settings, paths, thresholds, and networking defaults.
All settings can be overridden via environment variables with NETWATCH_ prefix.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory for the NetWatch repository
REPO_ROOT: Path = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Central configuration parameters for NetWatch."""

    model_config = SettingsConfigDict(
        env_prefix="NETWATCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    db_path: str = Field(
        default=str(REPO_ROOT / "netwatch.db"),
        validation_alias=AliasChoices("NETWATCH_DB_PATH", "NETWATCH_DB", "db_path"),
        description="Path to SQLite database file",
    )
    db_timeout_seconds: float = Field(
        default=30.0,
        validation_alias=AliasChoices("NETWATCH_DB_TIMEOUT", "NETWATCH_DB_TIMEOUT_SECONDS", "db_timeout_seconds"),
        description="SQLite lock timeout in seconds",
    )

    # Network Capture & Discovery
    interface: str = Field(
        default="auto",
        validation_alias=AliasChoices("NETWATCH_INTERFACE", "NETWATCH_IFACE", "interface"),
        description="Interface to capture on ('auto' detects default route interface)",
    )
    subnet: str = Field(
        default="auto",
        validation_alias=AliasChoices("NETWATCH_SUBNET", "subnet"),
        description="Subnet CIDR string ('auto' computes from interface IP and mask)",
    )
    gateway_ip: str = Field(
        default="auto",
        validation_alias=AliasChoices("NETWATCH_GATEWAY_IP", "NETWATCH_GATEWAY", "gateway_ip"),
        description="Default gateway IP ('auto' auto-detects from OS routing table)",
    )
    probe_interval_seconds: float = Field(
        default=5.0,
        validation_alias=AliasChoices("NETWATCH_PROBE_INTERVAL", "probe_interval_seconds"),
        description="Interval in seconds between active gateway latency probes (default: 5s)",
    )
    probe_window_size: int = Field(
        default=20,
        validation_alias=AliasChoices("NETWATCH_PROBE_WINDOW", "probe_window_size"),
        description="Number of probes in rolling latency and packet loss window (default: 20)",
    )
    probe_timeout_seconds: float = Field(
        default=1.5,
        validation_alias=AliasChoices("NETWATCH_PROBE_TIMEOUT", "probe_timeout_seconds"),
        description="Timeout in seconds for single ping probe response",
    )

    # Discovery Service Settings
    discovery_interval_seconds: float = Field(
        default=30.0,
        validation_alias=AliasChoices("NETWATCH_DISCOVERY_INTERVAL", "NETWATCH_DISCOVERY_INTERVAL_SECONDS", "discovery_interval_seconds"),
        description="Interval in seconds between ARP discovery sweeps (default: 30s)",
    )
    arp_timeout_seconds: float = Field(
        default=2.0,
        validation_alias=AliasChoices("NETWATCH_ARP_TIMEOUT", "NETWATCH_ARP_TIMEOUT_SECONDS", "arp_timeout_seconds"),
        description="Timeout in seconds for Scapy ARP sweep responses",
    )
    dns_timeout_seconds: float = Field(
        default=0.8,
        validation_alias=AliasChoices("NETWATCH_DNS_TIMEOUT", "dns_timeout_seconds"),
        description="Timeout in seconds for reverse DNS resolution per IP",
    )
    baseline_initial_devices: bool = Field(
        default=True,
        validation_alias=AliasChoices("NETWATCH_BASELINE_INITIAL_DEVICES", "baseline_initial_devices"),
        description="Mark all devices discovered during initial sweep as is_known=1 (baseline)",
    )
    offline_threshold_sweeps: int = Field(
        default=2,
        validation_alias=AliasChoices("NETWATCH_OFFLINE_THRESHOLD_SWEEPS", "offline_threshold_sweeps"),
        description="Number of missed sweeps before marking an online device as offline (default: 2)",
    )
    oui_file_path: str = Field(
        default=str(REPO_ROOT / "backend" / "data" / "oui.csv"),
        validation_alias=AliasChoices("NETWATCH_OUI_FILE", "oui_file_path"),
        description="Local path to MAC OUI vendor mapping CSV",
    )

    # Traffic Aggregation & Sniffing
    bpf_filter: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("NETWATCH_BPF_FILTER", "bpf_filter"),
        description="Optional Berkeley Packet Filter (BPF) syntax string (e.g. 'ip or ip6')",
    )
    promiscuous_mode: bool = Field(
        default=True,
        validation_alias=AliasChoices("NETWATCH_PROMISC", "NETWATCH_PROMISCUOUS", "promiscuous_mode"),
        description="Enable promiscuous mode on the capture interface",
    )
    sniffer_queue_maxsize: int = Field(
        default=10000,
        validation_alias=AliasChoices("NETWATCH_QUEUE_MAXSIZE", "sniffer_queue_maxsize"),
        description="Maximum capacity of in-memory sniffer queue before dropping packets",
    )
    stats_interval_seconds: float = Field(
        default=10.0,
        validation_alias=AliasChoices("NETWATCH_STATS_INTERVAL", "stats_interval_seconds"),
        description="Interval in seconds for logging capture rate statistics (pps)",
    )
    agg_window_seconds: float = Field(
        default=5.0,
        validation_alias=AliasChoices("NETWATCH_AGG_WINDOW", "NETWATCH_AGG_WINDOW_SECONDS", "agg_window_seconds"),
        description="Aggregation window length in seconds",
    )
    flush_interval_seconds: float = Field(
        default=1.0,
        validation_alias=AliasChoices("NETWATCH_FLUSH_INTERVAL", "NETWATCH_FLUSH_INTERVAL_SECONDS", "flush_interval_seconds"),
        description="Interval to flush batched packet flows to database",
    )
    batch_size: int = Field(
        default=250,
        validation_alias=AliasChoices("NETWATCH_BATCH_SIZE", "batch_size"),
        description="Maximum packets or records to hold before immediate DB flush",
    )
    retention_hours: float = Field(
        default=24.0,
        validation_alias=AliasChoices("NETWATCH_RETENTION_HOURS", "retention_hours"),
        description="Hours to retain packet flows and traffic metrics",
    )

    # API Server
    api_host: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("NETWATCH_API_HOST", "api_host"),
        description="FastAPI bind host address",
    )
    api_port: int = Field(
        default=8000,
        validation_alias=AliasChoices("NETWATCH_API_PORT", "NETWATCH_PORT", "api_port"),
        description="FastAPI HTTP port",
    )

    # ML Score & Alert Thresholds
    model_path: str = Field(
        default=str(REPO_ROOT / "backend" / "ml" / "model.joblib"),
        validation_alias=AliasChoices("NETWATCH_MODEL_PATH", "model_path"),
        description="Path to serialized IsolationForest model.joblib",
    )
    model_contamination: float = Field(
        default=0.02,
        validation_alias=AliasChoices("NETWATCH_CONTAMINATION", "model_contamination"),
        description="IsolationForest contamination factor (default: 0.02)",
    )
    min_training_samples: int = Field(
        default=20,
        validation_alias=AliasChoices("NETWATCH_MIN_TRAINING_SAMPLES", "min_training_samples"),
        description="Minimum feature samples required to train IsolationForest",
    )
    alert_cooldown_seconds: float = Field(
        default=30.0,
        validation_alias=AliasChoices("NETWATCH_ALERT_COOLDOWN", "alert_cooldown_seconds"),
        description="Cooldown duration in seconds to suppress duplicate alert spam per IP and type",
    )
    anomaly_threshold: float = Field(
        default=0.70,
        validation_alias=AliasChoices("NETWATCH_ANOMALY_THRESHOLD", "NETWATCH_ML_SCORE_THRESHOLD", "anomaly_threshold"),
        description="Minimum anomaly score (0.0 - 1.0) to register an AI alert",
    )
    warning_threshold: float = Field(
        default=0.60,
        validation_alias=AliasChoices("NETWATCH_WARNING_THRESHOLD", "warning_threshold"),
        description="Score threshold for warning level alert",
    )
    critical_threshold: float = Field(
        default=0.85,
        validation_alias=AliasChoices("NETWATCH_CRITICAL_THRESHOLD", "critical_threshold"),
        description="Score threshold for critical level alert",
    )

    # Heuristic Rule-Based Threat Detection Thresholds
    rule_port_scan_threshold: int = Field(
        default=25,
        validation_alias=AliasChoices("NETWATCH_RULE_PORT_SCAN_THRESHOLD", "rule_port_scan_threshold"),
        description="Unique destination ports threshold to trigger port_scan alert",
    )
    rule_port_scan_high_threshold: int = Field(
        default=75,
        validation_alias=AliasChoices("NETWATCH_RULE_PORT_SCAN_HIGH", "rule_port_scan_high_threshold"),
        description="Unique destination ports threshold for high severity port_scan",
    )
    rule_syn_flood_count: int = Field(
        default=80,
        validation_alias=AliasChoices("NETWATCH_RULE_SYN_COUNT", "rule_syn_flood_count"),
        description="TCP SYN count threshold to trigger syn_flood alert",
    )
    rule_syn_flood_ratio: float = Field(
        default=0.70,
        validation_alias=AliasChoices("NETWATCH_RULE_SYN_RATIO", "rule_syn_flood_ratio"),
        description="SYN-to-TCP ratio threshold to trigger syn_flood alert",
    )
    rule_syn_flood_high_count: int = Field(
        default=250,
        validation_alias=AliasChoices("NETWATCH_RULE_SYN_HIGH_COUNT", "rule_syn_flood_high_count"),
        description="TCP SYN count threshold for high severity syn_flood",
    )
    rule_icmp_flood_count: int = Field(
        default=100,
        validation_alias=AliasChoices("NETWATCH_RULE_ICMP_COUNT", "rule_icmp_flood_count"),
        description="ICMP packet count threshold to trigger icmp_flood alert",
    )
    rule_icmp_flood_high_count: int = Field(
        default=300,
        validation_alias=AliasChoices("NETWATCH_RULE_ICMP_HIGH_COUNT", "rule_icmp_flood_high_count"),
        description="ICMP packet count threshold for high severity icmp_flood",
    )
    rule_bandwidth_hog_bytes: int = Field(
        default=4_000_000,
        validation_alias=AliasChoices("NETWATCH_RULE_BANDWIDTH_BYTES", "rule_bandwidth_hog_bytes"),
        description="Bytes transmitted threshold in 5s window to trigger bandwidth_hog alert (~6.4 Mbps)",
    )
    rule_bandwidth_hog_high_bytes: int = Field(
        default=15_000_000,
        validation_alias=AliasChoices("NETWATCH_RULE_BANDWIDTH_HIGH_BYTES", "rule_bandwidth_hog_high_bytes"),
        description="Bytes transmitted threshold for high severity bandwidth_hog (~24 Mbps)",
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("NETWATCH_LOG_LEVEL", "log_level"),
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    # Cached network discovery
    _cached_net_info: Optional[Any] = None

    def get_network_info(self, refresh: bool = False) -> Any:
        """Retrieve or detect network configuration dynamically.

        Args:
            refresh: If True, bypass cached network information and re-detect.

        Returns:
            NetworkInfo object with interface, ip, subnet, gateway, etc.
        """
        # Lazy import to avoid circular dependency
        from backend.discovery import detect_network_info

        if self._cached_net_info is None or refresh:
            self._cached_net_info = detect_network_info(
                interface_name=self.interface if self.interface.lower() != "auto" else None,
                subnet_override=self.subnet if self.subnet.lower() != "auto" else None,
                gateway_override=self.gateway_ip if self.gateway_ip.lower() != "auto" else None,
            )
        return self._cached_net_info

    @property
    def resolved_interface(self) -> str:
        """Resolved capture network interface."""
        return self.get_network_info().interface

    @property
    def resolved_ip(self) -> str:
        """Resolved local IP address."""
        return self.get_network_info().ip

    @property
    def resolved_subnet(self) -> str:
        """Resolved subnet CIDR notation."""
        return self.get_network_info().subnet

    @property
    def resolved_gateway(self) -> Optional[str]:
        """Resolved default gateway IP address."""
        return self.get_network_info().gateway

    @property
    def absolute_db_path(self) -> Path:
        """Absolute Path object to the SQLite database file."""
        return Path(self.db_path).resolve()


# Singleton global configuration instance
settings = Settings()


def setup_logging(level: Optional[str] = None) -> None:
    """Configure unified logging for NetWatch processes."""
    lvl_name = level or settings.log_level
    numeric_level = getattr(logging, lvl_name.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# Apply default logging configuration on import
setup_logging()
