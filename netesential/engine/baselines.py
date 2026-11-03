"""
NetSentinel - Stage 2 Dynamic Statistical Baseline Engine
Author: Hardik
Developer / Organization: Hidden Eye Security

Calculates streaming statistical baselines and identifies subtle anomalies:
  1. Exponential Moving Average (EMA) for updating mean baseline without memory bloating:
     mu_t = alpha * x_t + (1 - alpha) * mu_{t-1} (alpha = 0.1)
  2. Robust Outlier Scoring using Median Absolute Deviation (MAD):
     M_i = (0.6745 * (x_i - median)) / MAD
     Triggers statistical alert when M_i > 3.5.
  3. Strict warm-up suppression during initial 500 packets.
  4. Explainable alert decoration with MITRE ATT&CK mappings.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import uuid
import time
from collections import deque
from typing import Dict, Any, Optional, List
import numpy as np

from config import settings


class Stage2StatisticalEngine:
    """
    Online statistical baseline engine computing robust running metrics
    and modified Z-score anomaly detection across packet byte lengths and rates.
    """

    def __init__(
        self,
        alpha: float = settings.EMA_ALPHA,
        modified_z_threshold: float = settings.MAD_MODIFIED_Z_THRESHOLD,
        warmup_packet_count: int = settings.WARMUP_PACKET_COUNT,
        rolling_window_size: int = settings.ROLLING_WINDOW_SIZE,
    ):
        self.alpha = alpha
        self.modified_z_threshold = modified_z_threshold
        self.warmup_packet_count = warmup_packet_count
        self.rolling_window_size = rolling_window_size

        # Telemetry state
        self.total_packets_observed: int = 0

        # Global/Per-metric rolling windows (using deque for bounded memory)
        self._packet_lengths: deque[float] = deque(maxlen=self.rolling_window_size)

        # Running Exponential Moving Average (EMA)
        self._length_ema: Optional[float] = None

    @property
    def is_warmed_up(self) -> bool:
        """Returns True if the engine has ingested enough telemetry to exit warm-up."""
        return self.total_packets_observed > self.warmup_packet_count

    def update_ema(self, new_val: float) -> float:
        """
        Updates the Exponential Moving Average:
        mu_t = alpha * x_t + (1 - alpha) * mu_{t-1}
        """
        if self._length_ema is None:
            self._length_ema = new_val
        else:
            self._length_ema = (self.alpha * new_val) + ((1.0 - self.alpha) * self._length_ema)
        return self._length_ema

    def compute_mad_score(self, new_val: float) -> tuple[float, float, float]:
        """
        Computes Modified Z-score (M_i) using rolling median and MAD:
        M_i = 0.6745 * (x_i - median) / MAD
        Returns (m_score, median, mad).
        """
        if len(self._packet_lengths) < 10:
            return 0.0, new_val, 0.0

        arr = np.array(self._packet_lengths, dtype=np.float64)
        median = float(np.median(arr))
        abs_deviations = np.abs(arr - median)
        mad = float(np.median(abs_deviations))

        # Handle zero-MAD condition (e.g. uniform packet sizes in buffer)
        if mad == 0.0:
            mean_ad = float(np.mean(abs_deviations))
            if mean_ad > 0.0:
                # Fallback to mean absolute deviation with normal consistency factor
                denom = 1.2533 * mean_ad
                m_score = (0.6745 * (new_val - median)) / denom
            else:
                if new_val == median:
                    m_score = 0.0
                else:
                    # Non-zero outlier relative to identical baseline
                    m_score = abs(new_val - median) / max(median * 0.1, 1.0)
        else:
            m_score = (0.6745 * (new_val - median)) / mad

        return m_score, median, mad

    def evaluate(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Ingests flow dictionary, updates online baselines, and returns an
        explainable AlertRecord dictionary if Modified Z-score exceeds 3.5
        (and warm-up threshold is satisfied).
        """
        self.total_packets_observed += 1

        packet_len = float(flow.get("packet_length", 0))
        src_ip = flow.get("source_ip", "")
        dst_ip = flow.get("destination_ip", "")
        dst_port = flow.get("destination_port")
        protocol = flow.get("protocol", "UNKNOWN")
        ts = float(flow.get("timestamp", time.time()))

        # Update EMA and rolling window
        current_ema = self.update_ema(packet_len)
        m_score, median, mad = self.compute_mad_score(packet_len)

        # Append current observation to rolling window for future evaluations
        self._packet_lengths.append(packet_len)

        # Enforce Warm-Up Suppression Rule
        if not self.is_warmed_up:
            return None

        # Check if outlier threshold exceeded
        if m_score > self.modified_z_threshold:
            severity = "CRITICAL" if m_score > 7.0 else "HIGH"
            trigger_reason = (
                f"Statistical payload size anomaly: packet length {packet_len:.0f} bytes generated "
                f"Modified Z-score of {m_score:.2f} (threshold: {self.modified_z_threshold:.1f}). "
                f"Rolling median: {median:.1f} bytes, MAD: {mad:.2f}, EMA: {current_ema:.1f} bytes."
            )

            return {
                "alert_id": str(uuid.uuid4()),
                "timestamp": ts,
                "severity": severity,
                "detection_source": "Stage 2 Statistical",
                "mitre_tactic": "TA0010: Exfiltration",
                "mitre_technique": "T1041: Exfiltration Over C2",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": protocol,
                "trigger_reason": trigger_reason,
                "observed_value": round(packet_len, 2),
                "baseline_expected": round(median, 2),
                "deviation_score": round(m_score, 2),
            }

        return None
