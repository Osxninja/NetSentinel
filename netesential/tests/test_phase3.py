"""
NetSentinel - Phase 3 Verification Test Suite
Tests (EC)² Multi-Agent Investigation Framework:
  1. Knowledge Graph entity & relationship retrieval.
  2. Forensic traffic querying over SQLite flow logs.
  3. Payload sanitization and privacy redaction.
  4. End-to-end 8-agent directed graph workflow.
"""

import os
import sqlite3
import tempfile
import pytest

from investigation.knowledge_graph import NetworkTopologyKG
from investigation.traffic_tool import TrafficAnalysisTool
from investigation.workflow import MultiAgentInvestigationWorkflow
from investigation.agents import sanitize_payloads


def test_knowledge_graph_retrieval():
    """Verifies that the Knowledge Graph resolves IP metadata and topology relationships."""
    kg = NetworkTopologyKG()
    info = kg.get_device_info("192.168.1.100")

    assert info["role"] == "Finance Specialist Workstation"
    assert info["department"] == "Finance"
    assert info["mac"] == "F8:75:A4:12:34:56"
    assert "10.0.0.1" in info["authorized_peers"]

    # Natural language query resolution
    query_res = kg.query("What is the role and subnet of 10.0.0.1?")
    entities = query_res["resolved_entities"]
    assert "10.0.0.1" in entities
    assert "Domain Controller" in entities["10.0.0.1"]["role"]


def test_traffic_tool_forensic_queries():
    """Verifies forensic queries over SQLite flow_logs table."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db = tf.name

    conn = sqlite3.connect(temp_db)
    conn.execute(
        """
        CREATE TABLE flow_logs (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_length INTEGER,
            tcp_flags TEXT,
            window_size INTEGER
        )
        """
    )
    # Insert test flows
    conn.execute(
        "INSERT INTO flow_logs VALUES (1, 1000.0, '192.168.1.100', '10.0.0.5', 50000, 80, 'TCP', 64, 'S', 65535)"
    )
    conn.execute(
        "INSERT INTO flow_logs VALUES (2, 1001.0, '192.168.1.100', '10.0.0.5', 50000, 443, 'TCP', 128, 'SA', 65535)"
    )
    conn.commit()
    conn.close()

    try:
        tool = TrafficAnalysisTool(db_path=temp_db)
        summary = tool.get_flow_summary("192.168.1.100")
        assert summary["total_packets"] == 2
        assert summary["total_bytes"] == 192

        flags = tool.get_tcp_flag_distribution("192.168.1.100")
        assert flags.get("S") == 1
        assert flags.get("SA") == 1
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_payload_privacy_redaction():
    """Verifies recursive sanitization of raw packet payloads."""
    raw_event = {
        "source_ip": "192.168.1.50",
        "payload": "GET /etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        "nested": {
            "raw_data_hex": "0x41414141414141",
            "protocol": "HTTP",
        },
    }
    sanitized = sanitize_payloads(raw_event)
    assert sanitized["payload"] == "[REDACTED_PAYLOAD]"
    assert sanitized["nested"]["raw_data_hex"] == "[REDACTED_PAYLOAD]"
    assert sanitized["nested"]["protocol"] == "HTTP"


def test_multi_agent_investigation_workflow_end_to_end():
    """
    Executes the complete 8-agent (EC)² workflow on a Port Scanning alert.
    Verifies:
      - Stage A: Questions generated & evidence retrieved.
      - Stage B: 3 hypotheses evaluated (Attack supported, Scanner refuted).
      - Stage C: Accurate executive report generated and approved.
    """
    workflow = MultiAgentInvestigationWorkflow()

    alert = {
        "alert_id": "ALERT-TEST-001",
        "timestamp": 1700000000.0,
        "severity": "HIGH",
        "detection_source": "Stage 1 Heuristics",
        "mitre_tactic": "TA0007: Discovery",
        "mitre_technique": "T1046: Network Service Discovery",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "protocol": "TCP",
        "trigger_reason": "Port scanning cadence detected: probed 25 unique destination ports.",
        "observed_value": 25.0,
        "baseline_expected": 20.0,
        "deviation_score": 1.25,
    }

    result = workflow.run_investigation(alert)

    # 1. Structure Verification
    assert "investigation_id" in result
    assert "stage_a_initial_context" in result
    assert "stage_b_evaluated_hypotheses" in result
    assert "stage_c_final_deliverable" in result

    # 2. Stage B Hypothesis Verification
    hypotheses = result["stage_b_evaluated_hypotheses"]
    assert len(hypotheses) == 3

    attack_hyp = [h for h in hypotheses if "Reconnaissance" in h["title"]][0]
    scanner_hyp = [h for h in hypotheses if "Scanner" in h["title"]][0]

    assert attack_hyp["status"] == "Supported"
    assert scanner_hyp["status"] == "Refuted"

    # 3. Stage C Verification
    final_deliverable = result["stage_c_final_deliverable"]
    assert final_deliverable["review_status"] == "VERIFIED_ACCURATE"
    assert final_deliverable["grounding_check"]["hallucinations_detected"] is False

    approved_report = final_deliverable["approved_report"]
    assert "192.168.1.100" in approved_report["executive_summary"]
    assert len(approved_report["recommended_actions"]) >= 3
