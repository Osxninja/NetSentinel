"""
NetSentinel - Autonomous Investigation Worker
Author: Hardik
Developer / Organization: Hidden Eye Security

Continuously listens for detected alerts and runs the (EC)² Multi-Agent
Investigation graph asynchronously, persisting reports into SQLite.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import json
import sqlite3
import logging
import threading
import queue
from typing import Dict, Any, Optional, List, Callable

from investigation.workflow import MultiAgentInvestigationWorkflow
from config import settings

logger = logging.getLogger("netsentinel.auto_investigation")


class AutonomousInvestigationWorker(threading.Thread):
    """
    Background worker that monitors an alert queue, runs the (EC)² Multi-Agent
    investigation graph on incoming alerts, updates SQLite records with full
    investigation reports, and notifies listeners.
    """

    def __init__(
        self,
        alert_queue: queue.Queue,
        db_path: str = settings.DB_PATH,
        on_report_ready: Optional[Callable[[Dict[str, Any], Dict[str, Any]], None]] = None,
        max_history: int = 100,
    ):
        super().__init__(name="AutoInvestigationWorker", daemon=True)
        self.alert_queue = alert_queue
        self.db_path = db_path
        self.on_report_ready = on_report_ready
        self.max_history = max_history
        self._stop_event = threading.Event()
        self.workflow = MultiAgentInvestigationWorkflow()
        self.completed_reports: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.reports_generated_count = 0

    def run(self) -> None:
        logger.info("Autonomous (EC)² Investigation Worker started.")
        while not self._stop_event.is_set():
            try:
                alert = self.alert_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._process_alert(alert)
            except Exception as e:
                logger.error("Error investigating alert %s: %s", alert.get("alert_id"), e, exc_info=True)
            finally:
                if hasattr(self.alert_queue, "task_done"):
                    try:
                        self.alert_queue.task_done()
                    except Exception:
                        pass

        logger.info("Autonomous (EC)² Investigation Worker stopped.")

    def stop(self) -> None:
        self._stop_event.set()

    def _process_alert(self, alert: Dict[str, Any]) -> None:
        alert_id = alert.get("alert_id")
        logger.info("Auto-investigating alert %s (%s - %s)", alert_id, alert.get("severity"), alert.get("mitre_technique"))

        # Run multi-agent workflow
        report = self.workflow.run_investigation(alert)
        report_json = json.dumps(report, indent=2)

        # Update SQLite alerts table
        self._persist_report_to_db(alert_id, report_json)

        # Store in-memory history
        with self._lock:
            self.completed_reports.append({
                "alert_id": alert_id,
                "timestamp": alert.get("timestamp"),
                "severity": alert.get("severity"),
                "technique": alert.get("mitre_technique"),
                "report": report,
            })
            if len(self.completed_reports) > self.max_history:
                self.completed_reports.pop(0)
            self.reports_generated_count += 1

        # Notify callback if registered
        if self.on_report_ready:
            try:
                self.on_report_ready(alert, report)
            except Exception as cb_err:
                logger.error("Error in on_report_ready callback: %s", cb_err)

    def _persist_report_to_db(self, alert_id: Optional[str], report_json: str) -> None:
        if not alert_id:
            return
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            with conn:
                conn.execute(
                    "UPDATE alerts SET investigation_report = ? WHERE alert_id = ?",
                    (report_json, alert_id),
                )
            conn.close()
        except sqlite3.OperationalError as e:
            logger.warning("Could not persist report to SQLite (table might be initializing): %s", e)
        except Exception as e:
            logger.error("Failed to update alert %s with report: %s", alert_id, e)

    def get_latest_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.completed_reports[-limit:])

    def get_report_by_alert_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for item in reversed(self.completed_reports):
                if item["alert_id"] == alert_id:
                    return item["report"]

        # Fallback to query SQLite directly
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cur = conn.cursor()
            cur.execute("SELECT investigation_report FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                return json.loads(row[0])
        except Exception as e:
            logger.error("Error reading report from DB for %s: %s", alert_id, e)
        return None
