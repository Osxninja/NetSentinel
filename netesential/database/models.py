"""
NetSentinel - Database Models
Author: Hardik
Developer / Organization: Hidden Eye Security

Declarative SQLAlchemy models for FlowLog, AlertRecord, and SystemCommand entities.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import uuid
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column,
    Integer,
    Float,
    String,
    Text,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class FlowLog(Base):
    """
    Represents an ingested network packet/flow telemetry record.
    Indexed for fast range queries on timestamp, IP addresses, and ports.
    """
    __tablename__ = "flow_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, index=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    packet_length: Mapped[int] = mapped_column(Integer, nullable=False)
    tcp_flags: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    window_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("ix_flow_src_dst_time", "source_ip", "destination_ip", "timestamp"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
            "window_size": self.window_size,
        }


class AlertRecord(Base):
    """
    Represents an explainable cybersecurity anomaly detection alert.
    Tagged with MITRE ATT&CK classifications and mathematical deviation scores.
    """
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    timestamp: Mapped[float] = mapped_column(Float, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    detection_source: Mapped[str] = mapped_column(String(50), nullable=False)  # Stage 1 Heuristics, Stage 2 Statistical
    mitre_tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    mitre_technique: Mapped[str] = mapped_column(String(100), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    trigger_reason: Mapped[str] = mapped_column(Text, nullable=False)
    observed_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    baseline_expected: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    deviation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    investigation_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_alert_src_time", "source_ip", "timestamp"),
        Index("ix_alert_severity", "severity"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "detection_source": self.detection_source,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "trigger_reason": self.trigger_reason,
            "observed_value": self.observed_value,
            "baseline_expected": self.baseline_expected,
            "deviation_score": self.deviation_score,
            "investigation_report": self.investigation_report,
        }


class SystemCommand(Base):
    """
    Commands dispatched via the Web Dashboard or external controllers
    for live execution by the NetSentinel orchestrator engine.
    """
    __tablename__ = "system_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, index=True, nullable=False)
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "command": self.command,
            "status": self.status,
            "output": self.output,
        }
