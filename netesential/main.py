"""
NetSentinel - Autonomous All-in-One Cybersecurity Anomaly Detection & SOC Engine
Author: Hardik
Developer / Organization: Hidden Eye Security

Integrates:
  1. Live Computer Packet Ingestion (Raw socket / psutil hybrid zero-privilege capture).
  2. Asynchronous SQLite WAL Batch Persistence (500ms / 250 record batching).
  3. Multi-Stage Detection Engine:
     - Stage 1: Deterministic Heuristic Rules (Port scans, PPS surges, C2 ports).
     - Stage 2: Dynamic Statistical Baselines (EMA + MAD Modified Z-score M_i > 3.5).
     - Stage 3: Online Machine Learning Isolation Forest (10D multivariate feature vector).
  4. Autonomous (EC)² Multi-Agent Graph Investigation & Plain-English Reporting.
  5. Live Streamlit SOC Dashboard (Hardware telemetry, active sockets, alert feeds).
  6. Dedicated Interactive NetSentinel CLI Shell (`netsentinel> `).
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import os
import sys
import time
import queue
import signal
import socket
import logging
import asyncio
import argparse
import threading
import subprocess
import webbrowser
from typing import Dict, Any, List, Optional

# Force UTF-8 encoding on Windows console to prevent charmap errors
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

import config
from config import settings
from database.connection import get_async_engine, init_db
from ingestion.batch_writer import AsyncBatchWriter
from ingestion.sniffer import PacketSnifferThread
from engine.rules import Stage1RuleEngine
from engine.baselines import Stage2StatisticalEngine
from engine.ml_engine import MLAnomalyDetector
from engine.pc_telemetry import get_pc_telemetry
from investigation.auto_worker import AutonomousInvestigationWorker

# Setup Logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netsentinel.main")
console = Console()


class NetSentinelSystem:
    """
    Master orchestrator running all NetSentinel subsystems in a single execution.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        dashboard_port: int = 8501,
        launch_dashboard: bool = True,
        enable_ml: bool = True,
        ml_contamination: float = 0.05,
    ):
        self.interface = interface
        self.dashboard_port = dashboard_port
        self.launch_dashboard = launch_dashboard
        self.enable_ml = enable_ml
        self.ml_contamination = ml_contamination

        # State & Thread management
        self._running = False
        self._stop_event = threading.Event()
        self.start_time = time.time()
        self.dashboard_process: Optional[subprocess.Popen] = None

        # Telemetry counters
        self.total_packets_captured = 0
        self.total_alerts_detected = 0
        self.recent_alerts: List[Dict[str, Any]] = []
        self._alerts_lock = threading.Lock()

        # Detection Engines
        self.stage1_engine = Stage1RuleEngine()
        self.stage2_engine = Stage2StatisticalEngine()
        self.ml_engine = MLAnomalyDetector(contamination=ml_contamination, min_samples_to_train=30) if enable_ml else None

        # Concurrency Queues
        self.raw_packet_queue: queue.Queue = queue.Queue(maxsize=settings.BUFFER_MAXSIZE)
        self.db_packet_queue: queue.Queue = queue.Queue(maxsize=settings.BUFFER_MAXSIZE)
        self.alert_queue: queue.Queue = queue.Queue(maxsize=1000)

        # Subsystems
        self.engine = get_async_engine()
        self.writer: Optional[AsyncBatchWriter] = None
        self.writer_thread: Optional[threading.Thread] = None
        self.writer_loop: Optional[asyncio.AbstractEventLoop] = None
        self.sniffer: Optional[PacketSnifferThread] = None
        self.dispatcher_thread: Optional[threading.Thread] = None
        self.investigation_worker: Optional[AutonomousInvestigationWorker] = None

    def start(self) -> None:
        """Starts all background subsystems."""
        self._running = True

        # 1. Initialize SQLite Database with WAL PRAGMAs
        self.writer_loop = asyncio.new_event_loop()
        self.writer_loop.run_until_complete(init_db(self.engine))

        # 2. Start Async Persistence Batch Writer in a dedicated thread
        self.writer = AsyncBatchWriter(engine=self.engine, packet_queue=self.db_packet_queue)

        def _run_writer_loop():
            asyncio.set_event_loop(self.writer_loop)
            self.writer_loop.run_until_complete(self.writer.run())

        self.writer_thread = threading.Thread(target=_run_writer_loop, name="AsyncBatchWriterThread", daemon=True)
        self.writer_thread.start()

        # 3. Start Autonomous Investigation Worker
        self.investigation_worker = AutonomousInvestigationWorker(
            alert_queue=self.alert_queue,
            db_path=settings.DB_PATH,
            on_report_ready=self._on_report_generated,
        )
        self.investigation_worker.start()

        # 4. Start Pipeline Dispatcher Thread (Processes flows, runs Stage 1, 2, and ML)
        self.dispatcher_thread = threading.Thread(target=self._run_dispatcher, name="PipelineDispatcher", daemon=True)
        self.dispatcher_thread.start()

        # 5. Start Live Packet Sniffer (Scapy raw socket / psutil live socket hybrid)
        self.sniffer = PacketSnifferThread(
            packet_queue=self.raw_packet_queue,
            interface=self.interface,
            prune_layers=False,
        )
        self.sniffer.start()

        # 6. Launch Streamlit Web Dashboard Subprocess
        if self.launch_dashboard:
            self._start_dashboard_subprocess()

    def _start_dashboard_subprocess(self) -> None:
        dashboard_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.py")
        env = os.environ.copy()
        env["NETSENTINEL_DB_PATH"] = settings.DB_PATH
        env["PYTHONIOENCODING"] = "utf-8"

        cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            dashboard_script,
            "--server.port",
            str(self.dashboard_port),
            "--server.headless",
            "true",
            "--browser.gatherUsageStats",
            "false",
        ]
        try:
            self.dashboard_process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Auto-open browser in background thread
            def _open_browser():
                time.sleep(2.0)
                try:
                    webbrowser.open_new_tab(f"http://localhost:{self.dashboard_port}")
                except Exception:
                    pass

            threading.Thread(target=_open_browser, daemon=True).start()
        except Exception as e:
            console.print(f"[yellow][!] Could not auto-launch Streamlit dashboard: {e}[/yellow]")

    def _check_system_commands(self) -> None:
        """Polls for commands dispatched from the Web Dashboard."""
        import sqlite3
        try:
            conn = sqlite3.connect(settings.DB_PATH, timeout=2.0)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, command FROM system_commands WHERE status = 'PENDING' ORDER BY id ASC")
            rows = cur.fetchall()
            for r in rows:
                cid = r["id"]
                cmd = r["command"]
                output = self._execute_remote_command(cmd)
                cur.execute("UPDATE system_commands SET status = 'PROCESSED', output = ? WHERE id = ?", (output, cid))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _execute_remote_command(self, cmd_line: str) -> str:
        """Executes a command dispatched remotely from the Web Dashboard."""
        parts = cmd_line.strip().split()
        if not parts:
            return ""
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "status":
            uptime = time.time() - self.start_time
            pps = self.total_packets_captured / max(1.0, uptime)
            return (
                f"[SYSTEM STATUS]\n"
                f"Uptime: {uptime:.1f}s | Ingestion: {pps:.1f} PPS\n"
                f"Packets Captured: {self.total_packets_captured:,} | Alerts Triggered: {self.total_alerts_detected}\n"
                f"ML Engine: {'Active' if (self.ml_engine and self.ml_engine.is_trained) else 'Learning'}\n"
                f"Dashboard: http://localhost:{self.dashboard_port}"
            )
        elif cmd in ("pc", "sys"):
            t = get_pc_telemetry()
            return (
                f"[PC TELEMETRY]\n"
                f"Host: {t.get('hostname')} | Primary IP: {t.get('primary_ip')} | OS: {t.get('os_platform')}\n"
                f"CPU Load: {t.get('cpu_percent')}% | RAM Load: {t.get('ram_percent')}%\n"
                f"RAM Usage: {t.get('ram_used_gb', 0):.1f} / {t.get('ram_total_gb', 0):.1f} GB\n"
                f"Active Sockets: {t.get('active_sockets')}"
            )
        elif cmd == "simulate":
            mode = args[0] if args else "scan"
            self.inject_simulation(mode)
            return f"[SIMULATION] Dispatched {mode.upper()} attack scenario into live pipeline."
        elif cmd == "ml":
            if not self.enable_ml or not self.ml_engine:
                return "[ML] Isolation Forest engine disabled."
            return (
                f"[ML ISOLATION FOREST]\n"
                f"Model: IsolationForest(n_estimators=100, contamination={self.ml_engine.contamination})\n"
                f"Trained: {self.ml_engine.is_trained} | Samples in Buffer: {len(self.ml_engine.feature_buffer)}/{self.ml_engine.max_buffer_size}\n"
                f"Total Flows Scored: {self.ml_engine.total_flows_evaluated:,} | Refit Interval: {self.ml_engine.refit_interval}"
            )
        elif cmd == "alerts":
            with self._alerts_lock:
                recent = list(self.recent_alerts[-5:])
            if not recent:
                return "[ALERTS] No security alerts in current buffer."
            lines = [f"[RECENT ALERTS ({len(recent)})]"]
            for a in recent:
                lines.append(f"• [{a['severity']}] {a['mitre_technique']} ({a['source_ip']} -> {a['destination_ip']}:{a.get('destination_port')})")
            return "\n".join(lines)
        elif cmd in ("report", "inv"):
            target_id = args[0] if args else "latest"
            if not self.investigation_worker:
                return "[REPORT] Investigation worker not active."
            if target_id.lower() == "latest":
                reps = self.investigation_worker.get_latest_reports(1)
                rep = reps[0]["report"] if reps else None
            else:
                rep = self.investigation_worker.get_report_by_alert_id(target_id)
            if not rep:
                return f"[REPORT] No investigation report found for '{target_id}'."
            deliverable = rep.get("stage_c_final_deliverable", {})
            summary = deliverable.get("executive_summary") or deliverable.get("approved_report", {}).get("executive_summary", "No summary.")
            return f"[INVESTIGATION DELIVERABLE {rep.get('investigation_id')}]\n{summary}"
        else:
            return f"[COMMAND] Unknown: '{cmd_line}'. Type 'status', 'pc', 'alerts', 'report', 'ml', or 'simulate scan|c2|dos'."

    def _run_dispatcher(self) -> None:
        """
        Consumes live raw packets from `raw_packet_queue`:
        1. Passes to DB queue for SQLite batch persistence.
        2. Evaluates Stage 1 deterministic heuristic rules.
        3. Evaluates Stage 2 dynamic statistical baselines.
        4. Evaluates Stage 3 online ML Isolation Forest.
        5. Forwards any alerts to SQLite and Autonomous Investigation worker.
        6. Processes remote commands from Web Dashboard.
        """
        last_cmd_check = time.time()
        while not self._stop_event.is_set():
            now = time.time()
            if now - last_cmd_check > 0.3:
                self._check_system_commands()
                last_cmd_check = now

            try:
                flow = self.raw_packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            self.total_packets_captured += 1

            # 1. Enqueue for database persistence
            try:
                self.db_packet_queue.put_nowait(flow)
            except queue.Full:
                pass

            # 2. Run Analytics Pipeline
            alerts: List[Dict[str, Any]] = []

            # Stage 1 Heuristics
            s1 = self.stage1_engine.evaluate(flow)
            if s1:
                alerts.extend(s1)

            # Stage 2 Statistical Baselines
            s2 = self.stage2_engine.evaluate(flow)
            if s2:
                alerts.append(s2)

            # Stage 3 Machine Learning
            if self.enable_ml and self.ml_engine:
                s3 = self.ml_engine.evaluate(flow)
                if s3:
                    alerts.append(s3)

            # Handle Alerts
            if alerts:
                self._handle_detected_alerts(alerts)

            self.raw_packet_queue.task_done()

    def _handle_detected_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Persists alerts, queues them for multi-agent investigation, and notifies CLI."""
        for a in alerts:
            with self._alerts_lock:
                self.total_alerts_detected += 1
                self.recent_alerts.append(a)
                if len(self.recent_alerts) > 100:
                    self.recent_alerts.pop(0)

            # Persist directly to SQLite alerts table
            self._persist_alert_record(a)

            # Enqueue for Autonomous Multi-Agent Investigation
            try:
                self.alert_queue.put_nowait(a)
            except queue.Full:
                pass

            # Real-time console alert notification banner
            severity_style = "bold red" if a["severity"] == "CRITICAL" else "bold yellow"
            console.print(
                f"\n[{severity_style}][! ALERT !][/{severity_style}] "
                f"[bold white]{a['mitre_technique']}[/bold white] "
                f"({a['detection_source']}) from [cyan]{a['source_ip']}[/cyan] -> "
                f"[cyan]{a['destination_ip']}:{a.get('destination_port')}[/cyan]\n"
                f"       [dim]Reason: {a['trigger_reason'][:95]}[/dim]"
            )

    def _persist_alert_record(self, alert: Dict[str, Any]) -> None:
        import sqlite3
        try:
            conn = sqlite3.connect(settings.DB_PATH, timeout=5.0)
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO alerts (
                        alert_id, timestamp, severity, detection_source,
                        mitre_tactic, mitre_technique, source_ip, destination_ip,
                        destination_port, protocol, trigger_reason, observed_value,
                        baseline_expected, deviation_score, investigation_report
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert["alert_id"],
                        alert["timestamp"],
                        alert["severity"],
                        alert["detection_source"],
                        alert["mitre_tactic"],
                        alert["mitre_technique"],
                        alert["source_ip"],
                        alert["destination_ip"],
                        alert.get("destination_port"),
                        alert["protocol"],
                        alert["trigger_reason"],
                        alert.get("observed_value"),
                        alert.get("baseline_expected"),
                        alert.get("deviation_score"),
                        alert.get("investigation_report"),
                    ),
                )
            conn.close()
        except Exception as e:
            logger.error("Failed to persist alert %s: %s", alert.get("alert_id"), e)

    def _on_report_generated(self, alert: Dict[str, Any], report: Dict[str, Any]) -> None:
        inv_id = report.get("investigation_id", alert.get("alert_id", "")[:8])
        exec_time = report.get("execution_duration_seconds", 0.0)
        deliverable = report.get("stage_c_final_deliverable", {})
        title = deliverable.get("approved_report", {}).get("incident_title") or deliverable.get("executive_summary", "")[:60]

        console.print(
            f"[bold green][+ EC² AGENT REPORT READY][/bold green] "
            f"Investigation [cyan]{inv_id}[/cyan] ({exec_time}s) on Alert [yellow]{alert.get('alert_id')}[/yellow]\n"
            f"    [dim]Type 'report latest' or 'report {alert.get('alert_id')}' to read the full report.[/dim]"
        )

    def inject_simulation(self, mode: str = "scan") -> None:
        """Injects realistic attack patterns into the active stream to verify detection."""
        now = time.time()
        mode = mode.lower().strip()

        if mode == "scan":
            console.print("[bold cyan][*] Injecting Horizontal Port Scan attack simulation (T1046)...[/bold cyan]")
            for p in range(1, 26):
                flow = {
                    "timestamp": now + (p * 0.01),
                    "source_ip": "192.168.1.188",
                    "destination_ip": "10.0.0.5",
                    "source_port": 45000 + p,
                    "destination_port": p,
                    "protocol": "TCP",
                    "packet_length": 60,
                    "tcp_flags": "S",
                    "window_size": 1024,
                }
                self.raw_packet_queue.put(flow)

        elif mode == "c2":
            console.print("[bold cyan][*] Injecting Data Exfiltration / C2 Payload attack simulation (T1041)...[/bold cyan]")
            # Send small warmup then huge payload
            flow = {
                "timestamp": now,
                "source_ip": "192.168.1.188",
                "destination_ip": "10.0.0.5",
                "source_port": 49152,
                "destination_port": 1433,
                "protocol": "TCP",
                "packet_length": 5800,
                "tcp_flags": "PA",
                "window_size": 65535,
            }
            self.raw_packet_queue.put(flow)

        elif mode == "dos":
            console.print("[bold cyan][*] Injecting Volumetric DoS PPS Burst attack simulation (T1498)...[/bold cyan]")
            for i in range(120):
                flow = {
                    "timestamp": now + (i * 0.003),
                    "source_ip": "192.168.1.199",
                    "destination_ip": "10.0.0.1",
                    "source_port": 50000,
                    "destination_port": 80,
                    "protocol": "UDP",
                    "packet_length": 512,
                    "tcp_flags": None,
                    "window_size": None,
                }
                self.raw_packet_queue.put(flow)
        else:
            console.print(f"[red]Unknown simulation mode '{mode}'. Choose 'scan', 'c2', or 'dos'.[/red]")

    def stop(self) -> None:
        """Gracefully terminates all subsystems."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()

        console.print("[cyan][*] Shutting down NetSentinel subsystems...[/cyan]")

        # 1. Stop Sniffer
        if self.sniffer:
            self.sniffer.stop()

        # 2. Stop Auto Investigation Worker
        if self.investigation_worker:
            self.investigation_worker.stop()

        # 3. Stop Persistence Writer
        if self.writer:
            self.writer._stop_requested = True
        if self.writer_thread and self.writer_thread.is_alive():
            self.writer_thread.join(timeout=3.0)

        # 4. Stop Dashboard Subprocess
        if self.dashboard_process:
            try:
                self.dashboard_process.terminate()
                self.dashboard_process.wait(timeout=2.0)
            except Exception:
                try:
                    self.dashboard_process.kill()
                except Exception:
                    pass

        # 5. Dispose Async Engine
        if self.writer_loop and self.writer_loop.is_running():
            self.writer_loop.call_soon_threadsafe(self.writer_loop.stop)

        console.print("[green][+] NetSentinel shutdown complete. All data flushed to SQLite.[/green]")


def run_interactive_cli(system: NetSentinelSystem) -> None:
    """
    Dedicated interactive CLI shell (`netsentinel> `) allowing real-time monitoring,
    diagnostics, alert reviews, and multi-agent report inspection without leaving the tool.
    """
    banner_text = (
        "[bold cyan][NetSentinel] Autonomous Cybersecurity Anomaly Detection & SOC Engine[/bold cyan]\n"
        "[bold magenta]Lead Developer: Hardik | Security Research: Hidden Eye Security[/bold magenta]\n"
        "[dim]Live Capture | Stage 1 Heuristics | Stage 2 Statistical Baselines | ML Isolation Forest | (EC)2 Multi-Agent RAG[/dim]\n\n"
        f"[green]* Ingestion Mode:[/green] Continuous Live Computer Traffic Monitoring\n"
        f"[green]* Web Dashboard:[/green]  [link=http://localhost:{system.dashboard_port}]http://localhost:{system.dashboard_port}[/link]\n"
        f"[green]* Database Engine:[/green] SQLite WAL Mode ({settings.DB_PATH})\n"
        "[yellow]Type 'help' to view available commands or 'exit' to shut down.[/yellow]"
    )
    console.print(Panel(banner_text, border_style="cyan"))

    while system._running:
        try:
            cmd_line = input("\nnetsentinel> ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Received interrupt signal. Exiting...[/yellow]")
            break

        if not cmd_line:
            continue

        parts = cmd_line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit", "q", "stop"):
            console.print("[yellow]Initiating graceful shutdown...[/yellow]")
            break

        elif cmd == "help":
            _print_help()

        elif cmd in ("status", "stat", "info"):
            _print_status(system)

        elif cmd in ("pc", "sys", "system"):
            _print_pc_telemetry()

        elif cmd in ("alerts", "alert"):
            _print_alerts(system)

        elif cmd in ("report", "inv", "investigate"):
            target_id = args[0] if args else "latest"
            _print_report(system, target_id)

        elif cmd == "ml":
            _print_ml_status(system)

        elif cmd == "simulate":
            mode = args[0] if args else "scan"
            system.inject_simulation(mode)

        elif cmd in ("dashboard", "dash", "web"):
            url = f"http://localhost:{system.dashboard_port}"
            console.print(f"[bold cyan]Opening NetSentinel Dashboard:[/bold cyan] {url}")
            try:
                webbrowser.open(url)
            except Exception:
                pass

        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")

        else:
            console.print(f"[red]Unknown command: '{cmd}'. Type 'help' to see valid commands.[/red]")


def _print_help() -> None:
    table = Table(title="NetSentinel Interactive Commands", show_header=True, header_style="bold cyan")
    table.add_column("Command", style="bold green", width=22)
    table.add_column("Description", style="white")

    table.add_row("status", "Show live packet throughput (PPS), alerts, and worker statuses.")
    table.add_row("pc", "Show live PC diagnostic telemetry (CPU %, RAM %, IP, Active Sockets).")
    table.add_row("alerts", "List detected security incidents with severity, endpoints, and reasons.")
    table.add_row("report [id|latest]", "Inspect full (EC)² Multi-Agent forensic investigation and containment report.")
    table.add_row("ml", "Show Machine Learning Isolation Forest online learning status and feature metrics.")
    table.add_row("simulate <scan|c2|dos>", "Inject a realistic attack pattern into the live stream to test detection.")
    table.add_row("dashboard", "Open the live Streamlit SOC Web Dashboard in your default browser.")
    table.add_row("clear", "Clear terminal screen.")
    table.add_row("exit / quit", "Safely stop all packet capture threads, flush database, and exit.")
    console.print(table)


def _print_status(system: NetSentinelSystem) -> None:
    uptime = time.time() - system.start_time
    pps = system.total_packets_captured / max(1.0, uptime)
    
    table = Table(title="NetSentinel Subsystem Operational Status", show_header=True, header_style="bold yellow")
    table.add_column("Component", style="cyan")
    table.add_column("Status / Metric", style="bold white")

    table.add_row("System Uptime", f"{uptime:.1f} seconds")
    table.add_row("Live Packets Captured", f"{system.total_packets_captured:,} frames")
    table.add_row("Current Ingestion Rate", f"{pps:.1f} packets/second")
    table.add_row("Security Alerts Triggered", f"{system.total_alerts_detected} alerts")
    
    rep_count = system.investigation_worker.reports_generated_count if system.investigation_worker else 0
    table.add_row("(EC)^2 Multi-Agent Reports", f"{rep_count} completed investigations")

    ml_status = "Trained & Active" if (system.ml_engine and system.ml_engine.is_trained) else "Learning / Warming Up"
    table.add_row("ML Isolation Forest", ml_status)
    table.add_row("Streamlit Web Dashboard", f"http://localhost:{system.dashboard_port}")
    console.print(table)


def _print_pc_telemetry() -> None:
    try:
        t = get_pc_telemetry()
    except Exception as e:
        console.print(f"[red]Failed to read PC telemetry: {e}[/red]")
        return

    table = Table(title="Host Machine Hardware & Network Diagnostics", show_header=True, header_style="bold green")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Host Device Name", t.get("hostname", "Unknown"))
    table.add_row("Primary IP Address", t.get("primary_ip", "127.0.0.1"))
    table.add_row("Operating System", t.get("os_platform", sys.platform))
    table.add_row("CPU Utilization", f"{t.get('cpu_percent', 0.0)}%")
    table.add_row("RAM Utilization", f"{t.get('ram_percent', 0.0)}% ({t.get('ram_used_gb', 0.0):.1f} / {t.get('ram_total_gb', 0.0):.1f} GB)")
    table.add_row("Active Network Sockets", str(t.get("active_sockets", 0)))
    table.add_row("Active Network Interfaces", ", ".join(t.get("network_interfaces", [])))
    console.print(table)


def _print_alerts(system: NetSentinelSystem) -> None:
    with system._alerts_lock:
        alerts = list(system.recent_alerts[-25:])

    if not alerts:
        console.print("[dim]No security alerts detected yet. Run 'simulate scan' to inject test traffic.[/dim]")
        return

    table = Table(title=f"Recent Detected Security Incidents (Last {len(alerts)})", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold red", width=10)
    table.add_column("Source", style="cyan", width=22)
    table.add_column("MITRE Technique", style="yellow", width=30)
    table.add_column("Endpoint", style="white", width=30)
    table.add_column("Alert ID", style="dim", width=12)

    for a in alerts:
        sev_color = "red" if a["severity"] == "CRITICAL" else "yellow"
        table.add_row(
            f"[{sev_color}]{a['severity']}[/{sev_color}]",
            a["detection_source"],
            a["mitre_technique"],
            f"{a['source_ip']} -> {a['destination_ip']}:{a.get('destination_port')}",
            a.get("alert_id", "")[:8],
        )
    console.print(table)


def _print_report(system: NetSentinelSystem, target_id: str) -> None:
    if not system.investigation_worker:
        console.print("[red]Autonomous investigation worker is not running.[/red]")
        return

    report = None
    if target_id.lower() == "latest":
        reports = system.investigation_worker.get_latest_reports(limit=1)
        if reports:
            report = reports[0]["report"]
            target_id = reports[0]["alert_id"]
    else:
        report = system.investigation_worker.get_report_by_alert_id(target_id)

    if not report:
        console.print(f"[yellow]No investigation report found for '{target_id}'. If an alert just fired, allow ~1 second for (EC)² agents to finalize synthesis.[/yellow]")
        return

    deliverable = report.get("stage_c_final_deliverable", {})
    summary = deliverable.get("executive_summary") or deliverable.get("approved_report", {}).get("executive_summary", "No summary.")
    actions = deliverable.get("containment_recommendations") or deliverable.get("approved_report", {}).get("recommended_actions", [])
    hypotheses = report.get("stage_b_evaluated_hypotheses", [])

    body = f"[bold]Investigation ID:[/bold] {report.get('investigation_id')}\n"
    body += f"[bold]Duration:[/bold] {report.get('execution_duration_seconds', 0.0)}s\n\n"
    body += f"[bold yellow]Executive Summary:[/bold yellow]\n{summary}\n\n"

    if hypotheses:
        body += "[bold cyan]Evaluated Hypotheses:[/bold cyan]\n"
        for h in hypotheses:
            sym = "[green][+][/green]" if h.get("status") == "SUPPORTED" else "[red][-][/red]" if h.get("status") == "REFUTED" else "[yellow][?][/yellow]"
            body += f"  {sym} [bold]{h.get('hypothesis_id')}[/bold] ({h.get('status')}): {h.get('statement')}\n"
        body += "\n"

    if actions:
        body += "[bold green]Recommended SOC Containment Actions:[/bold green]\n"
        for act in actions:
            body += f"  * {act}\n"

    console.print(Panel(body, title=f"[bold]Incident Investigation Deliverable ({target_id[:8]})[/bold]", border_style="green"))


def _print_ml_status(system: NetSentinelSystem) -> None:
    if not system.enable_ml or not system.ml_engine:
        console.print("[yellow]Machine Learning Anomaly Engine is disabled.[/yellow]")
        return

    ml = system.ml_engine
    table = Table(title="Machine Learning Isolation Forest Engine Status", show_header=True, header_style="bold blue")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Algorithm", "Scikit-Learn IsolationForest (Online 10D Ensembles)")
    table.add_row("Model Trained", "Yes (Online Active)" if ml.is_trained else f"No ({len(ml.feature_buffer)}/{ml.min_samples_to_train} baseline samples gathered)")
    table.add_row("Contamination Ratio", f"{ml.contamination * 100:.1f}%")
    table.add_row("Sliding Feature Buffer Size", f"{len(ml.feature_buffer)} / {ml.max_buffer_size}")
    table.add_row("Total Flows Evaluated", f"{ml.total_flows_evaluated:,}")
    table.add_row("Refit Interval", f"Every {ml.refit_interval} samples")
    table.add_row("Extracted Feature Space", ", ".join(ml.FEATURE_NAMES))
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetSentinel: All-in-One Live Network Anomaly Detection, Machine Learning & Autonomous SOC Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example Usage:
  python main.py                     # Start full system with live capture & web dashboard
  python main.py --no-dashboard      # Run in headless CLI mode
  python main.py --port 8080         # Run web dashboard on custom port 8080
  python main.py --simulate-test     # Inject realistic test attack on startup to verify alerts & reporting
        """
    )
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface to capture (default: auto-detect)")
    parser.add_argument("-p", "--port", type=int, default=8501, help="Streamlit SOC Web Dashboard port (default: 8501)")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable automatic launch of Streamlit web dashboard")
    parser.add_argument("--no-ml", action="store_true", help="Disable Machine Learning Isolation Forest detector")
    parser.add_argument("--ml-contamination", type=float, default=0.05, help="Isolation Forest anomaly contamination rate (default: 0.05)")
    parser.add_argument("--simulate-test", action="store_true", help="Inject test attack simulation on startup to verify end-to-end detection")

    args = parser.parse_args()

    # Instantiate system
    system = NetSentinelSystem(
        interface=args.interface,
        dashboard_port=args.port,
        launch_dashboard=not args.no_dashboard,
        enable_ml=not args.no_ml,
        ml_contamination=args.ml_contamination,
    )

    # Start all subsystems
    system.start()

    # Optional startup attack simulation
    if args.simulate_test:
        time.sleep(1.0)
        system.inject_simulation("scan")
        system.inject_simulation("c2")

    # Enter Interactive Tool CLI Shell
    try:
        run_interactive_cli(system)
    finally:
        system.stop()


if __name__ == "__main__":
    main()
