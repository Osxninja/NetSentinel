"""
NetSentinel - Phase 2 Verification Test Suite
Tests Stage 1 deterministic rules (port scanning, PPS spike, backdoor ports)
and Stage 2 statistical anomaly detection (EMA, MAD Modified Z-score, warm-up suppression).
"""

import time
import pytest
from engine.rules import Stage1RuleEngine
from engine.baselines import Stage2StatisticalEngine
from engine.detector_worker import DetectorProcess


def test_stage1_port_scan_detection_nmap_pattern():
    """
    Simulates an nmap-style horizontal port scan:
    Source IP 192.168.1.100 scans 25 unique ports on 10.0.0.5 within 1 second.
    Verifies that Stage 1 triggers a T1046 Network Service Discovery alert.
    """
    engine = Stage1RuleEngine(port_scan_threshold=20, port_scan_window=5.0)
    alerts = []
    base_time = 1000.0

    # Probe 25 distinct destination ports
    for i in range(1, 26):
        flow = {
            "timestamp": base_time + (i * 0.02),  # 20ms apart = total 0.5s
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "source_port": 40000 + i,
            "destination_port": i,  # Ports 1 through 25
            "protocol": "TCP",
            "packet_length": 60,
            "tcp_flags": "S",
            "window_size": 1024,
        }
        detected = engine.evaluate(flow)
        alerts.extend(detected)

    # Filter for port scan alerts
    port_scan_alerts = [
        a for a in alerts if a["mitre_technique"] == "T1046: Network Service Discovery"
    ]
    assert len(port_scan_alerts) >= 1, "Expected port scan alert to be triggered"

    alert = port_scan_alerts[0]
    assert alert["severity"] == "HIGH"
    assert alert["mitre_tactic"] == "TA0007: Discovery"
    assert alert["source_ip"] == "192.168.1.100"
    assert alert["observed_value"] >= 21.0
    assert alert["baseline_expected"] == 20.0
    assert alert["deviation_score"] > 1.0
    assert "port scan" in alert["trigger_reason"].lower()


def test_stage1_pps_volume_spike_detection():
    """
    Simulates a volumetric DDoS spike:
    Source IP sends 120 packets in 0.5s (effective 240 PPS > 100 PPS threshold).
    Verifies that Stage 1 triggers a T1498 Network Denial of Service alert.
    """
    engine = Stage1RuleEngine(pps_threshold=100.0, pps_window=5.0)
    alerts = []
    base_time = 2000.0

    for i in range(120):
        flow = {
            "timestamp": base_time + (i * 0.004),  # 120 packets over ~0.48s
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.1",
            "source_port": 50000,
            "destination_port": 80,
            "protocol": "UDP",
            "packet_length": 512,
            "tcp_flags": None,
            "window_size": None,
        }
        detected = engine.evaluate(flow)
        alerts.extend(detected)

    pps_alerts = [
        a for a in alerts if a["mitre_technique"] == "T1498: Network Denial of Service"
    ]
    assert len(pps_alerts) >= 1, "Expected PPS volume spike alert"

    alert = pps_alerts[0]
    assert alert["severity"] == "HIGH"
    assert alert["mitre_tactic"] == "TA0040: Impact"
    assert alert["observed_value"] > 100.0


def test_stage1_anomalous_backdoor_port_mapping():
    """
    Verifies detection of connections targeting known backdoor / C2 ports (e.g. 4444).
    """
    engine = Stage1RuleEngine()
    flow = {
        "timestamp": 3000.0,
        "source_ip": "192.168.1.150",
        "destination_ip": "10.0.0.99",
        "source_port": 54321,
        "destination_port": 4444,  # Metasploit reverse shell default
        "protocol": "TCP",
        "packet_length": 128,
        "tcp_flags": "S",
        "window_size": 4096,
    }
    alerts = engine.evaluate(flow)
    assert len(alerts) >= 1
    assert alerts[0]["destination_port"] == 4444
    assert alerts[0]["mitre_tactic"] == "TA0011: Command and Control"
    assert alerts[0]["mitre_technique"] == "T1571: Non-Standard Port"


def test_stage2_warmup_suppression():
    """
    Verifies that during the initial 500 packets (warm-up phase),
    statistical alerts are strictly suppressed even if anomalous payloads occur.
    """
    engine = Stage2StatisticalEngine(
        warmup_packet_count=500,
        modified_z_threshold=3.5,
        rolling_window_size=100,
    )

    alerts = []
    base_time = 4000.0

    # Ingest 400 packets with an anomaly at packet #250
    for i in range(1, 401):
        # Normal packets ~100 bytes, packet #250 is 5000 bytes
        pkt_len = 5000 if i == 250 else (90 + (i % 20))
        flow = {
            "timestamp": base_time + (i * 0.01),
            "source_ip": "10.10.10.10",
            "destination_ip": "10.20.20.20",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": pkt_len,
            "tcp_flags": "PA",
            "window_size": 65535,
        }
        res = engine.evaluate(flow)
        if res:
            alerts.append(res)

    assert not engine.is_warmed_up, "Engine should still be in warm-up state at 400 packets"
    assert len(alerts) == 0, f"Expected 0 alerts during warm-up, but got {len(alerts)}"


def test_stage2_volume_anomaly_detection_after_warmup():
    """
    Verifies that after the 500-packet warm-up period, an anomalous packet
    with a Modified Z-score > 3.5 generates an explainable statistical alert.
    """
    engine = Stage2StatisticalEngine(
        warmup_packet_count=500,
        modified_z_threshold=3.5,
        rolling_window_size=100,
    )

    base_time = 5000.0

    # 1. Feed 505 normal baseline packets (satisfies warm-up)
    for i in range(1, 506):
        flow = {
            "timestamp": base_time + (i * 0.01),
            "source_ip": "10.10.10.10",
            "destination_ip": "10.20.20.20",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 64 + (i % 30),  # Baseline payload 64 to 94 bytes
            "tcp_flags": "A",
            "window_size": 32768,
        }
        alert = engine.evaluate(flow)
        assert alert is None, "Baseline traffic should not trigger alert"

    assert engine.is_warmed_up, "Engine should be warmed up after 505 packets"

    # 2. Inject an anomalous massive data chunk (e.g. 5,000 bytes exfiltration chunk)
    anomaly_flow = {
        "timestamp": base_time + (506 * 0.01),
        "source_ip": "10.10.10.10",
        "destination_ip": "10.20.20.20",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_length": 5000,  # Massive outlier compared to ~79 byte median
        "tcp_flags": "PA",
        "window_size": 65535,
    }

    alert = engine.evaluate(anomaly_flow)
    assert alert is not None, "Expected statistical outlier alert after warm-up"
    assert alert["detection_source"] == "Stage 2 Statistical"
    assert alert["mitre_tactic"] == "TA0010: Exfiltration"
    assert alert["mitre_technique"] == "T1041: Exfiltration Over C2"
    assert alert["deviation_score"] > 3.5, f"Expected M_i > 3.5, got {alert['deviation_score']}"
    assert alert["observed_value"] == 5000.0
    assert "Modified Z-score" in alert["trigger_reason"]


def test_detector_process_evaluation_pipeline():
    """
    Tests the combined evaluation pipeline within DetectorProcess.
    """
    import multiprocessing
    in_q = multiprocessing.Queue()
    detector = DetectorProcess(input_queue=in_q, db_path=":memory:")

    # Normal flow
    f1 = {
        "timestamp": 6000.0,
        "source_ip": "172.16.0.5",
        "destination_ip": "172.16.0.1",
        "source_port": 55555,
        "destination_port": 53,
        "protocol": "UDP",
        "packet_length": 72,
    }
    alerts1 = detector.evaluate_flow(f1)
    assert len(alerts1) == 0

    # Backdoor port flow
    f2 = {
        "timestamp": 6000.1,
        "source_ip": "172.16.0.5",
        "destination_ip": "172.16.0.1",
        "source_port": 55556,
        "destination_port": 31337,
        "protocol": "TCP",
        "packet_length": 80,
    }
    alerts2 = detector.evaluate_flow(f2)
    assert len(alerts2) >= 1
    assert alerts2[0]["destination_port"] == 31337
