"""
NetSentinel - Machine Learning Anomaly Detection Engine
Author: Hardik
Developer / Organization: Hidden Eye Security

Uses scikit-learn IsolationForest with online rolling multivariate feature extraction
to identify zero-day, multi-vector, and stealthy network anomalies.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import time
import uuid
import numpy as np
from collections import deque, defaultdict
from typing import Dict, Any, Optional, List, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class MLAnomalyDetector:
    """
    Online Machine Learning Anomaly Detection using Isolation Forest.
    Extracts 10-dimensional flow feature vectors and learns baseline
    multivariate network patterns dynamically on any network.
    """

    FEATURE_NAMES = [
        "packet_length",
        "src_port_norm",
        "dst_port_norm",
        "is_tcp",
        "is_udp",
        "is_syn",
        "is_rst",
        "delta_time",
        "rolling_pps",
        "unique_ports_ratio",
    ]

    def __init__(
        self,
        contamination: float = 0.05,
        min_samples_to_train: int = 50,
        refit_interval: int = 100,
        max_buffer_size: int = 1000,
    ):
        self.contamination = contamination
        self.min_samples_to_train = min_samples_to_train
        self.refit_interval = refit_interval
        self.max_buffer_size = max_buffer_size

        # Machine Learning Pipeline
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=1,
        )
        self.is_trained = False

        # Sliding Buffers
        self.feature_buffer: deque = deque(maxlen=self.max_buffer_size)
        self.samples_since_refit = 0
        self.total_flows_evaluated = 0

        # State tracking per source IP for temporal features
        self._last_pkt_time: Dict[str, float] = {}
        self._traffic_history: Dict[str, deque[Tuple[float, int]]] = defaultdict(deque)
        self._port_history: Dict[str, deque[Tuple[float, int]]] = defaultdict(deque)

        # Alert suppressors to avoid flood per IP
        self._last_alert_time: Dict[str, float] = {}

    def extract_features(self, flow: Dict[str, Any]) -> np.ndarray:
        """
        Converts a normalized network flow dictionary into a 10D numeric feature vector.
        """
        src_ip = flow.get("source_ip", "")
        dst_port = flow.get("destination_port") or 0
        src_port = flow.get("source_port") or 0
        proto = (flow.get("protocol") or "").upper()
        flags = (flow.get("tcp_flags") or "").upper()
        pkt_len = float(flow.get("packet_length", 0))
        ts = float(flow.get("timestamp", time.time()))

        # 1. Packet Length
        f_len = pkt_len

        # 2-3. Normalized Ports
        f_src_port = min(src_port / 65535.0, 1.0)
        f_dst_port = min(dst_port / 65535.0, 1.0)

        # 4-5. Protocol One-Hot
        f_is_tcp = 1.0 if "TCP" in proto else 0.0
        f_is_udp = 1.0 if "UDP" in proto else 0.0

        # 6-7. Flags
        f_is_syn = 1.0 if ("S" in flags and "A" not in flags) else 0.0
        f_is_rst = 1.0 if "R" in flags else 0.0

        # 8. Inter-arrival Delta Time
        last_t = self._last_pkt_time.get(src_ip, ts)
        delta_t = min(max(ts - last_t, 0.0), 10.0)
        self._last_pkt_time[src_ip] = ts

        # 9. Rolling PPS for Source IP
        th_dq = self._traffic_history[src_ip]
        th_dq.append((ts, int(pkt_len)))
        # Prune older than 5.0s
        while th_dq and th_dq[0][0] < (ts - 5.0):
            th_dq.popleft()
        effective_w = max(0.1, ts - th_dq[0][0]) if len(th_dq) > 1 else 1.0
        f_pps = len(th_dq) / effective_w

        # 10. Target Unique Ports in Window
        port_dq = self._port_history[src_ip]
        if dst_port:
            port_dq.append((ts, int(dst_port)))
        while port_dq and port_dq[0][0] < (ts - 5.0):
            port_dq.popleft()
        unique_ports = len({p for _, p in port_dq})
        f_port_ratio = min(unique_ports / 25.0, 2.0)

        return np.array([
            f_len,
            f_src_port,
            f_dst_port,
            f_is_tcp,
            f_is_udp,
            f_is_syn,
            f_is_rst,
            delta_t,
            f_pps,
            f_port_ratio,
        ], dtype=np.float64)

    def fit_model(self) -> None:
        """Fits or refits the Isolation Forest model on the accumulated buffer."""
        if len(self.feature_buffer) < self.min_samples_to_train:
            return

        X = np.array(list(self.feature_buffer), dtype=np.float64)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        self.samples_since_refit = 0

    def evaluate(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates flow using Machine Learning Isolation Forest.
        Returns a structured alert if an anomalous multivariate pattern is detected.
        """
        self.total_flows_evaluated += 1
        x = self.extract_features(flow)
        self.feature_buffer.append(x)
        self.samples_since_refit += 1

        # Train model if enough samples gathered, or refit periodically
        if not self.is_trained and len(self.feature_buffer) >= self.min_samples_to_train:
            self.fit_model()
        elif self.is_trained and self.samples_since_refit >= self.refit_interval:
            self.fit_model()

        if not self.is_trained:
            return None

        # Predict anomaly
        x_scaled = self.scaler.transform(x.reshape(1, -1))
        raw_score = float(self.model.decision_function(x_scaled)[0])
        pred = int(self.model.predict(x_scaled)[0])

        # Anomaly probability sigmoid mapping: lower decision function -> higher anomaly score
        anomaly_prob = 1.0 / (1.0 + np.exp(raw_score * 4.0))

        # Check threshold
        src_ip = flow.get("source_ip", "")
        ts = float(flow.get("timestamp", time.time()))

        if pred == -1 or anomaly_prob >= 0.70:
            # Check alert cooldown (prevent spamming same IP within 4 seconds)
            last_alert = self._last_alert_time.get(src_ip, 0.0)
            if (ts - last_alert) < 4.0:
                return None
            self._last_alert_time[src_ip] = ts

            # Identify dominant anomalous feature
            pkt_len = x[0]
            pps = x[8]
            unique_ports = x[9] * 25.0

            if unique_ports > 15:
                mitre_tactic = "TA0007: Discovery"
                mitre_technique = "T1046: Network Service Discovery"
                reason = f"ML Isolation Forest detected reconnaissance anomaly (Targeted {unique_ports:.0f} ports, score: {anomaly_prob:.2f})"
            elif pps > 80:
                mitre_tactic = "TA0040: Impact"
                mitre_technique = "T1498: Network Denial of Service"
                reason = f"ML Isolation Forest detected volumetric burst anomaly ({pps:.1f} PPS, score: {anomaly_prob:.2f})"
            elif pkt_len > 2500:
                mitre_tactic = "TA0010: Exfiltration"
                mitre_technique = "T1041: Exfiltration Over C2"
                reason = f"ML Isolation Forest detected payload outlier anomaly ({pkt_len:.0f} bytes, score: {anomaly_prob:.2f})"
            else:
                mitre_tactic = "TA0011: Command and Control"
                mitre_technique = "T1571: Non-Standard Port"
                reason = f"ML Isolation Forest detected multivariate flow anomaly (Confidence: {anomaly_prob:.2f}, Raw: {raw_score:.3f})"

            severity = "CRITICAL" if anomaly_prob >= 0.85 else "HIGH"

            return {
                "alert_id": str(uuid.uuid4()),
                "timestamp": ts,
                "severity": severity,
                "detection_source": "Stage 3 Machine Learning (Isolation Forest)",
                "mitre_tactic": mitre_tactic,
                "mitre_technique": mitre_technique,
                "source_ip": src_ip,
                "destination_ip": flow.get("destination_ip", ""),
                "destination_port": flow.get("destination_port"),
                "protocol": flow.get("protocol", "UNKNOWN"),
                "trigger_reason": reason,
                "observed_value": round(anomaly_prob, 3),
                "baseline_expected": 0.50,
                "deviation_score": round((anomaly_prob - 0.50) * 10.0, 2),
            }

        return None
