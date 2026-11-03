"""
NetSentinel - Stage 1 Deterministic Heuristics Rules Engine
Author: Hardik
Developer / Organization: Hidden Eye Security

Evaluates real-time packet flow telemetry against deterministic cybersecurity rules:
  1. Instantaneous PPS & BPS volumetric traffic spikes.
  2. Horizontal & vertical port scanning cadences.
  3. TCP connection failures (SYN-to-ACK ratios and excessive RST flags).
  4. Anomalous protocol-to-port mapping and suspicious backdoor ports.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import time
import uuid
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Set, Tuple

from config import settings


class Stage1RuleEngine:
    """
    Deterministic rule engine operating over sliding temporal windows.
    Detects high-confidence attack signatures and abnormal connection patterns.
    """

    SUSPICIOUS_PORTS: Set[int] = {
        4444,   # Metasploit Default Listener / Reverse Shell
        8888,   # Common Alternative HTTP / Proxy / Backdoor
        31337,  # Back Orifice / Elite Backdoors
        1337,   # Common CTF / Backdoor Port
        5555,   # Freeciv / Android ADB Unauthorized Remote Debugging
        6667,   # IRC C2 Infrastructure
        9001,   # Tor Default / Custom Shells
    }

    # Standard IANA Transport Port Mappings for cross-referencing
    STANDARD_PORT_MAPPINGS: Dict[int, str] = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
    }

    def __init__(
        self,
        pps_threshold: float = settings.PPS_THRESHOLD,
        bps_threshold: float = settings.BPS_THRESHOLD,
        pps_window: float = settings.PPS_WINDOW_SECONDS,
        port_scan_threshold: int = settings.PORT_SCAN_THRESHOLD,
        port_scan_window: float = settings.PORT_SCAN_WINDOW_SECONDS,
        syn_flood_threshold: int = settings.SYN_FLOOD_THRESHOLD,
        syn_ack_ratio_threshold: float = settings.SYN_ACK_RATIO_THRESHOLD,
        rst_count_threshold: int = settings.RST_COUNT_THRESHOLD,
    ):
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold
        self.pps_window = pps_window
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_ack_ratio_threshold = syn_ack_ratio_threshold
        self.rst_count_threshold = rst_count_threshold

        # Sliding window state per source IP: deque of (timestamp, packet_length)
        self._traffic_history: Dict[str, deque[Tuple[float, int]]] = defaultdict(deque)

        # Port scanning state per source IP: deque of (timestamp, destination_port)
        self._port_history: Dict[str, deque[Tuple[float, int]]] = defaultdict(deque)

        # TCP Flag state per source IP: deque of (timestamp, flag_type)
        self._tcp_flag_history: Dict[str, deque[Tuple[float, str]]] = defaultdict(deque)

        # Alert suppressors to prevent flood per source IP/rule within window
        self._last_alert_time: Dict[str, float] = {}

    def _prune_window(self, queue_obj: deque, current_time: float, window_size: float) -> None:
        """Removes entries older than (current_time - window_size)."""
        cutoff = current_time - window_size
        while queue_obj and queue_obj[0][0] < cutoff:
            queue_obj.popleft()

    def _should_suppress_alert(self, alert_key: str, current_time: float, cooldown: float = 3.0) -> bool:
        """Prevents repeated duplicate alerts for the same source within a cooldown period."""
        last_time = self._last_alert_time.get(alert_key, 0.0)
        if (current_time - last_time) < cooldown:
            return True
        self._last_alert_time[alert_key] = current_time
        return False

    def evaluate(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a single flow record against all deterministic rules.
        Returns a list of structured alert dictionaries (if any anomalies triggered).
        """
        alerts: List[Dict[str, Any]] = []
        src_ip = flow.get("source_ip", "")
        dst_ip = flow.get("destination_ip", "")
        dst_port = flow.get("destination_port")
        protocol = flow.get("protocol", "UNKNOWN")
        packet_len = flow.get("packet_length", 0)
        tcp_flags = flow.get("tcp_flags") or ""
        ts = float(flow.get("timestamp", time.time()))

        if not src_ip:
            return alerts

        # --- Rule 1: Traffic Volume Spikes (PPS and BPS) ---
        traffic_dq = self._traffic_history[src_ip]
        traffic_dq.append((ts, packet_len))
        self._prune_window(traffic_dq, ts, self.pps_window)

        if len(traffic_dq) > 1:
            effective_window = max(0.1, ts - traffic_dq[0][0])
            pps = len(traffic_dq) / effective_window
            total_bytes = sum(item[1] for item in traffic_dq)
            bps = total_bytes / effective_window

            if pps > self.pps_threshold:
                alert_key = f"{src_ip}:pps_spike"
                if not self._should_suppress_alert(alert_key, ts):
                    alerts.append({
                        "alert_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "severity": "HIGH",
                        "detection_source": "Stage 1 Heuristics",
                        "mitre_tactic": "TA0040: Impact",
                        "mitre_technique": "T1498: Network Denial of Service",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": dst_port,
                        "protocol": protocol,
                        "trigger_reason": (
                            f"Volumetric PPS spike detected from {src_ip}: "
                            f"{pps:.1f} PPS exceeds threshold of {self.pps_threshold:.1f} PPS "
                            f"over {self.pps_window}s window."
                        ),
                        "observed_value": round(pps, 2),
                        "baseline_expected": self.pps_threshold,
                        "deviation_score": round(pps / self.pps_threshold, 2),
                    })

            if bps > self.bps_threshold:
                alert_key = f"{src_ip}:bps_spike"
                if not self._should_suppress_alert(alert_key, ts):
                    alerts.append({
                        "alert_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "severity": "CRITICAL",
                        "detection_source": "Stage 1 Heuristics",
                        "mitre_tactic": "TA0010: Exfiltration",
                        "mitre_technique": "T1048: Exfiltration Over Alternative Protocol",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": dst_port,
                        "protocol": protocol,
                        "trigger_reason": (
                            f"Volumetric bandwidth spike detected from {src_ip}: "
                            f"{bps / 1024:.1f} KB/s exceeds threshold of {self.bps_threshold / 1024:.1f} KB/s."
                        ),
                        "observed_value": round(bps, 2),
                        "baseline_expected": self.bps_threshold,
                        "deviation_score": round(bps / self.bps_threshold, 2),
                    })

        # --- Rule 2: Port Scanning Cadence ---
        if dst_port is not None:
            port_dq = self._port_history[src_ip]
            port_dq.append((ts, int(dst_port)))
            self._prune_window(port_dq, ts, self.port_scan_window)

            unique_ports = {p for _, p in port_dq}
            if len(unique_ports) > self.port_scan_threshold:
                alert_key = f"{src_ip}:port_scan"
                if not self._should_suppress_alert(alert_key, ts):
                    alerts.append({
                        "alert_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "severity": "HIGH",
                        "detection_source": "Stage 1 Heuristics",
                        "mitre_tactic": "TA0007: Discovery",
                        "mitre_technique": "T1046: Network Service Discovery",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": dst_port,
                        "protocol": protocol,
                        "trigger_reason": (
                            f"Port scanning cadence detected from {src_ip}: probed {len(unique_ports)} "
                            f"unique destination ports within {self.port_scan_window}s window "
                            f"(threshold: {self.port_scan_threshold})."
                        ),
                        "observed_value": float(len(unique_ports)),
                        "baseline_expected": float(self.port_scan_threshold),
                        "deviation_score": round(len(unique_ports) / self.port_scan_threshold, 2),
                    })

        # --- Rule 3: TCP Connection Failures & SYN/RST Anomaly ---
        if protocol == "TCP" and tcp_flags:
            flag_dq = self._tcp_flag_history[src_ip]
            flag_str = str(tcp_flags).upper()

            if "S" in flag_str and "A" not in flag_str:
                flag_dq.append((ts, "SYN"))
            elif "A" in flag_str:
                flag_dq.append((ts, "ACK"))
            elif "R" in flag_str:
                flag_dq.append((ts, "RST"))

            self._prune_window(flag_dq, ts, 5.0)

            syn_count = sum(1 for _, f in flag_dq if f == "SYN")
            ack_count = sum(1 for _, f in flag_dq if f == "ACK")
            rst_count = sum(1 for _, f in flag_dq if f == "RST")

            # Check excessive RST flags
            if rst_count > self.rst_count_threshold:
                alert_key = f"{src_ip}:rst_cadence"
                if not self._should_suppress_alert(alert_key, ts):
                    alerts.append({
                        "alert_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "severity": "MEDIUM",
                        "detection_source": "Stage 1 Heuristics",
                        "mitre_tactic": "TA0007: Discovery",
                        "mitre_technique": "T1046: Network Service Discovery",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": dst_port,
                        "protocol": protocol,
                        "trigger_reason": (
                            f"Elevated TCP RST cadence from {src_ip}: {rst_count} RST frames "
                            f"observed in 5s window (threshold: {self.rst_count_threshold})."
                        ),
                        "observed_value": float(rst_count),
                        "baseline_expected": float(self.rst_count_threshold),
                        "deviation_score": round(rst_count / self.rst_count_threshold, 2),
                    })

            # Check abnormal SYN-to-ACK ratio (SYN Flood or aggressive half-open scanning)
            if syn_count >= self.syn_flood_threshold:
                ratio = syn_count / max(ack_count, 1)
                if ratio > self.syn_ack_ratio_threshold:
                    alert_key = f"{src_ip}:syn_flood"
                    if not self._should_suppress_alert(alert_key, ts):
                        alerts.append({
                            "alert_id": str(uuid.uuid4()),
                            "timestamp": ts,
                            "severity": "HIGH",
                            "detection_source": "Stage 1 Heuristics",
                            "mitre_tactic": "TA0040: Impact",
                            "mitre_technique": "T1499: Endpoint Denial of Service",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "destination_port": dst_port,
                            "protocol": protocol,
                            "trigger_reason": (
                                f"Elevated SYN-to-ACK ratio ({syn_count} SYNs : {ack_count} ACKs = {ratio:.1f}x) "
                                f"from {src_ip} indicates potential SYN flood or half-open scan."
                            ),
                            "observed_value": round(ratio, 2),
                            "baseline_expected": self.syn_ack_ratio_threshold,
                            "deviation_score": round(ratio / self.syn_ack_ratio_threshold, 2),
                        })

        # --- Rule 4: Anomalous Protocol/Port Mapping ---
        if dst_port is not None and int(dst_port) in self.SUSPICIOUS_PORTS:
            alert_key = f"{src_ip}:{dst_port}:backdoor_port"
            if not self._should_suppress_alert(alert_key, ts, cooldown=10.0):
                alerts.append({
                    "alert_id": str(uuid.uuid4()),
                    "timestamp": ts,
                    "severity": "HIGH",
                    "detection_source": "Stage 1 Heuristics",
                    "mitre_tactic": "TA0011: Command and Control",
                    "mitre_technique": "T1571: Non-Standard Port",
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "protocol": protocol,
                    "trigger_reason": (
                        f"Anomalous protocol/port interaction: {protocol} traffic directed to known "
                        f"suspicious/backdoor port {dst_port}."
                    ),
                    "observed_value": float(dst_port),
                    "baseline_expected": 0.0,
                    "deviation_score": 10.0,
                })

        return alerts
