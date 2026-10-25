"""Subprocess supervisor and orchestrator for NetWatch.

Launches and supervises all core NetWatch services:
- Network Discovery (backend.discovery)
- Packet Sniffer (backend.sniffer)
- Metrics Window Aggregator (backend.aggregator)
- Gateway Latency & Loss Probe (backend.probe)
- ML & Threat Anomaly Detector (backend.ml.detector)
- FastAPI REST Server & Static Frontend Host (backend.api)

Features:
- Prefixed and colorized console log streaming per service
- Automatic process supervision and crash restart with backoff
- Coordinated graceful shutdown on SIGINT / SIGTERM (Ctrl+C)
- Flag --no-capture for simulation mode without requiring root/pcap drivers
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.config import settings
from backend.db import init_db

# ANSI Color codes for readable console prefixes
COLORS = {
    "API": "\033[36m",         # Cyan
    "SNIFFER": "\033[32m",     # Green
    "AGGREGATOR": "\033[34m",  # Blue
    "PROBE": "\033[35m",       # Magenta
    "DETECTOR": "\033[33m",    # Yellow
    "DISCOVERY": "\033[37m",   # White
    "SYSTEM": "\033[1;31m",    # Bold Red
    "RESET": "\033[0m",
}


class ManagedService:
    """Represents a single managed NetWatch background subprocess."""

    def __init__(self, name: str, cmd: List[str], color: str = "") -> None:
        self.name = name
        self.cmd = cmd
        self.color = color or COLORS.get(name, "")
        self.process: Optional[subprocess.Popen[str]] = None
        self.thread: Optional[threading.Thread] = None
        self.restart_count = 0
        self.last_start_time = 0.0

    def start(self) -> None:
        """Launch the service subprocess and attach output stream reader."""
        self.last_start_time = time.time()
        # Enforce unbuffered output for real-time log streaming
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"

        self.process = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(REPO_ROOT),
            env=env,
        )

        self.thread = threading.Thread(
            target=self._stream_logs,
            name=f"Logger-{self.name}",
            daemon=True,
        )
        self.thread.start()

    def _stream_logs(self) -> None:
        """Read and prefix stdout lines from the child process."""
        if not self.process or not self.process.stdout:
            return

        prefix = f"{self.color}[{self.name:<10}]{COLORS['RESET']}"
        for line in iter(self.process.stdout.readline, ""):
            if line:
                sys.stdout.write(f"{prefix} {line}")
                sys.stdout.flush()

    def stop(self, timeout: float = 3.0) -> None:
        """Gracefully terminate the subprocess."""
        if not self.process or self.process.poll() is not None:
            return

        try:
            # On Windows terminate() sends TerminateProcess; on POSIX sends SIGTERM
            self.process.terminate()
            self.process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, Exception):
            try:
                self.process.kill()
            except Exception:
                pass


class NetWatchSupervisor:
    """Supervises all NetWatch background components with auto-restart on crash."""

    def __init__(
        self,
        interface: Optional[str] = None,
        no_capture: bool = False,
        api_port: Optional[int] = None,
        api_host: Optional[str] = None,
    ) -> None:
        self.interface = interface or settings.resolved_interface
        self.no_capture = no_capture
        self.api_port = api_port or settings.api_port
        self.api_host = api_host or settings.api_host
        self.services: Dict[str, ManagedService] = {}
        self.shutdown_requested = False
        self._init_services()

    def _init_services(self) -> None:
        """Configure CLI invocation commands for each managed component."""
        py = sys.executable

        # 1. API Server & Frontend Host
        api_cmd = [py, "-m", "backend.api", "--host", self.api_host, "--port", str(self.api_port)]
        self.services["API"] = ManagedService("API", api_cmd, COLORS["API"])

        # 2. Network Discovery
        disc_cmd = [py, "-m", "backend.discovery"]
        self.services["DISCOVERY"] = ManagedService("DISCOVERY", disc_cmd, COLORS["DISCOVERY"])

        # 3. Packet Sniffer
        if self.no_capture:
            # Simulation mode: generate synthetic packet flows
            sniffer_cmd = [py, "-m", "backend.sniffer", "--simulate"]
        else:
            sniffer_cmd = [py, "-m", "backend.sniffer", "--iface", self.interface]
        self.services["SNIFFER"] = ManagedService("SNIFFER", sniffer_cmd, COLORS["SNIFFER"])

        # 4. Traffic Window Aggregator
        agg_cmd = [py, "-m", "backend.aggregator"]
        self.services["AGGREGATOR"] = ManagedService("AGGREGATOR", agg_cmd, COLORS["AGGREGATOR"])

        # 5. Gateway Latency & Loss Probe
        probe_cmd = [py, "-m", "backend.probe"]
        self.services["PROBE"] = ManagedService("PROBE", probe_cmd, COLORS["PROBE"])

        # 6. ML Anomaly & Threat Detector
        det_cmd = [py, "-m", "backend.ml.detector"]
        self.services["DETECTOR"] = ManagedService("DETECTOR", det_cmd, COLORS["DETECTOR"])

    def start_all(self) -> None:
        """Initialize database and launch all services."""
        init_db()

        banner = (
            f"\n{'='*75}\n"
            f"  NetWatch Integrated Network Monitoring System\n"
            f"  Web Dashboard & API : http://{self.api_host if self.api_host != '0.0.0.0' else 'localhost'}:{self.api_port}\n"
            f"  Capture Interface   : {self.interface} ({'Simulation Mode' if self.no_capture else 'Live Capture'})\n"
            f"  Database Path       : {settings.db_path}\n"
            f"  Press Ctrl+C to stop all managed services.\n"
            f"{'='*75}\n"
        )
        print(banner)

        for name, service in self.services.items():
            print(f"{COLORS['SYSTEM']}[SUPERVISOR]{COLORS['RESET']} Starting {name}...")
            service.start()
            time.sleep(0.3)

    def monitor_loop(self) -> None:
        """Monitor subprocess health and auto-restart crashed services with backoff."""
        while not self.shutdown_requested:
            time.sleep(1.5)
            if self.shutdown_requested:
                break

            for name, service in self.services.items():
                if not service.process:
                    continue

                exit_code = service.process.poll()
                if exit_code is not None and not self.shutdown_requested:
                    service.restart_count += 1
                    uptime = time.time() - service.last_start_time

                    print(
                        f"\n{COLORS['SYSTEM']}[SUPERVISOR] WARNING: {name} exited with code {exit_code} "
                        f"(uptime: {uptime:.1f}s, restarts: {service.restart_count}). "
                        f"Auto-restarting in 2.0s...{COLORS['RESET']}\n"
                    )

                    time.sleep(2.0)
                    if not self.shutdown_requested:
                        service.start()

    def shutdown(self) -> None:
        """Terminate all child processes cleanly."""
        if self.shutdown_requested:
            return
        self.shutdown_requested = True

        print(f"\n{COLORS['SYSTEM']}[SUPERVISOR]{COLORS['RESET']} Stopping all NetWatch services (Ctrl+C received)...")
        for name, service in self.services.items():
            print(f"{COLORS['SYSTEM']}[SUPERVISOR]{COLORS['RESET']} Terminating {name}...")
            service.stop(timeout=2.0)

        print(f"{COLORS['SYSTEM']}[SUPERVISOR]{COLORS['RESET']} All services terminated cleanly. Good bye!")


def main() -> None:
    """CLI entrypoint for NetWatch orchestrator."""
    parser = argparse.ArgumentParser(description="NetWatch Process Supervisor and Orchestrator")
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Capture interface to monitor (default: auto-detected)",
    )
    parser.add_argument(
        "--no-capture",
        action="store_true",
        help="Run in simulation mode without requiring live raw packet capture",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="FastAPI bind port (default: 8000)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="FastAPI bind host (default: 0.0.0.0)",
    )

    args = parser.parse_args()

    supervisor = NetWatchSupervisor(
        interface=args.iface,
        no_capture=args.no_capture,
        api_port=args.port,
        api_host=args.host,
    )

    def _sig_handler(signum: int, frame: Any) -> None:
        supervisor.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    supervisor.start_all()
    supervisor.monitor_loop()


if __name__ == "__main__":
    main()
