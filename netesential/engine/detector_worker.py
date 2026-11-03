"""
NetSentinel - Multi-Process Anomaly Detection Worker
Author: Hardik
Developer / Organization: Hidden Eye Security

Runs Stage 1 deterministic rules and Stage 2 statistical engines
inside an isolated process, avoiding Python GIL contention.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import time
import queue
import sqlite3
import logging
import multiprocessing
from typing import Optional, List, Dict, Any

from config import settings
from engine.rules import Stage1RuleEngine
from engine.baselines import Stage2StatisticalEngine
from engine.ml_engine import MLAnomalyDetector

logger = logging.getLogger("netsentinel.detector")


class DetectorProcess(multiprocessing.Process):
    """
    Dedicated worker process decoupling CPU-intensive analytical rules,
    MAD outlier detection, and Machine Learning Isolation Forest from
    packet capture and persistence threads.
    """

    def __init__(
        self,
        input_queue: multiprocessing.Queue,
        alert_queue: Optional[multiprocessing.Queue] = None,
        db_path: str = settings.DB_PATH,
        stop_event: Optional[multiprocessing.Event] = None,
        name: str = "NetSentinel-DetectorProcess",
        enable_ml: bool = True,
        ml_contamination: float = 0.05,
    ):
        super().__init__(name=name, daemon=True)
        self.input_queue = input_queue
        self.alert_queue = alert_queue
        self.db_path = db_path
        self.stop_event = stop_event or multiprocessing.Event()
        self.enable_ml = enable_ml
        self.ml_contamination = ml_contamination

        # Engine instances
        self.stage1_engine = Stage1RuleEngine()
        self.stage2_engine = Stage2StatisticalEngine()
        self.ml_engine = MLAnomalyDetector(contamination=ml_contamination, min_samples_to_train=30) if enable_ml else None

        # Metrics
        self.flows_analyzed = 0
        self.alerts_generated = 0

    def evaluate_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes Stage 1 heuristic rules, Stage 2 statistical baselines,
        and Stage 3 Machine Learning Isolation Forest on a flow record.
        Returns a list of generated alerts (if any).
        """
        self.flows_analyzed += 1
        alerts: List[Dict[str, Any]] = []

        # Stage 1: Heuristic Rules Evaluation
        s1_alerts = self.stage1_engine.evaluate(flow)
        if s1_alerts:
            alerts.extend(s1_alerts)

        # Stage 2: Statistical Baseline Evaluation
        s2_alert = self.stage2_engine.evaluate(flow)
        if s2_alert:
            alerts.append(s2_alert)

        # Stage 3: Machine Learning Anomaly Detection Evaluation
        if self.enable_ml and self.ml_engine:
            ml_alert = self.ml_engine.evaluate(flow)
            if ml_alert:
                alerts.append(ml_alert)

        if alerts:
            self.alerts_generated += len(alerts)

        return alerts

    def _persist_alerts_sqlite(self, db_conn: sqlite3.Connection, alerts: List[Dict[str, Any]]) -> None:
        """
        Persists generated alerts directly into the SQLite database.
        """
        if not alerts:
            return

        cursor = db_conn.cursor()
        try:
            cursor.executemany(
                """
                INSERT INTO alerts (
                    alert_id, timestamp, severity, detection_source,
                    mitre_tactic, mitre_technique, source_ip, destination_ip,
                    destination_port, protocol, trigger_reason, observed_value,
                    baseline_expected, deviation_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        a["alert_id"],
                        a["timestamp"],
                        a["severity"],
                        a["detection_source"],
                        a["mitre_tactic"],
                        a["mitre_technique"],
                        a["source_ip"],
                        a["destination_ip"],
                        a.get("destination_port"),
                        a["protocol"],
                        a["trigger_reason"],
                        a.get("observed_value"),
                        a.get("baseline_expected"),
                        a.get("deviation_score"),
                    )
                    for a in alerts
                ],
            )
            db_conn.commit()
        except Exception as e:
            logger.error("Failed to persist alert batch: %s", e)
        finally:
            cursor.close()

    def run(self) -> None:
        """
        Main worker execution loop inside isolated OS process.
        """
        logger.info("DetectorProcess started. Connecting to DB at %s", self.db_path)

        # Open dedicated synchronous connection with WAL pragmas for this process
        db_conn = None
        try:
            db_conn = sqlite3.connect(self.db_path, timeout=5.0)
            db_conn.execute("PRAGMA journal_mode=WAL;")
            db_conn.execute("PRAGMA synchronous=NORMAL;")
            db_conn.execute("PRAGMA busy_timeout=5000;")
            db_conn.execute("PRAGMA temp_store=MEMORY;")
        except Exception as e:
            logger.warning("Could not establish direct SQLite connection: %s", e)

        while not self.stop_event.is_set():
            try:
                flow = self.input_queue.get(timeout=0.1)
            except (queue.Empty, TimeoutError):
                continue
            except Exception:
                break

            alerts = self.evaluate_flow(flow)
            if alerts:
                # Forward to alert queue if subscribed
                if self.alert_queue is not None:
                    for a in alerts:
                        try:
                            self.alert_queue.put_nowait(a)
                        except queue.Full:
                            pass

                # Persist to database
                if db_conn:
                    self._persist_alerts_sqlite(db_conn, alerts)

        # Drain remaining input queue upon stop
        while not self.input_queue.empty():
            try:
                flow = self.input_queue.get_nowait()
                alerts = self.evaluate_flow(flow)
                if alerts and db_conn:
                    self._persist_alerts_sqlite(db_conn, alerts)
            except queue.Empty:
                break

        if db_conn:
            db_conn.close()

        logger.info(
            "DetectorProcess exited. Flows analyzed: %d, Alerts generated: %d",
            self.flows_analyzed,
            self.alerts_generated,
        )

    def stop(self) -> None:
        """Signals the process to stop."""
        self.stop_event.set()
