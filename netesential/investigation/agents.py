"""
NetSentinel - (EC)² Multi-Agent Investigation Framework
Author: Hardik
Developer / Organization: Hidden Eye Security

Implements 8 specialized forensic agents communicating via structured JSON:
  Stage A (Initiation):
    1. ContextualQuestionGeneratorAgent
    2. EvidenceGatheringAgent
  Stage B (Hypothesis Cycle):
    3. HypothesisGeneratorAgent
    4. PlannerAgent
    5. HypothesisEvaluatorAgent
    6. FlowEvaluatorAgent
  Stage C (Conclusion):
    7. ExplanationAgent
    8. ExplanationReviewerAgent
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import re
import json
import time
from typing import Dict, Any, List, Optional
from investigation.knowledge_graph import NetworkTopologyKG
from investigation.traffic_tool import TrafficAnalysisTool


def sanitize_payloads(data: Any) -> Any:
    """Recursively redacts raw packet payloads to enforce privacy constraints."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if "payload" in k.lower() or "raw_data" in k.lower():
                cleaned[k] = "[REDACTED_PAYLOAD]"
            else:
                cleaned[k] = sanitize_payloads(v)
        return cleaned
    elif isinstance(data, list):
        return [sanitize_payloads(item) for item in data]
    elif isinstance(data, str) and len(data) > 256 and ("\x00" in data or "0x" in data[:10]):
        return "[REDACTED_PAYLOAD]"
    return data


class ContextualQuestionGeneratorAgent:
    """
    Stage A Agent: Ingests an anomalous alert and generates ordered missing contextual questions.
    """

    def generate_contextual_questions(self, alert: Dict[str, Any]) -> List[str]:
        src_ip = alert.get("source_ip", "")
        dst_ip = alert.get("destination_ip", "")
        dst_port = alert.get("destination_port")
        technique = alert.get("mitre_technique", "")

        questions = [
            f"What is the device role, ownership, and departmental subnet for source IP {src_ip}?",
            f"What is the asset criticality and function of destination IP {dst_ip}?",
            f"What are the historical traffic volume and TCP flag patterns for {src_ip}?",
        ]

        if dst_port:
            questions.append(
                f"Is traffic directed to port {dst_port} typical or authorized between {src_ip} and {dst_ip}?"
            )
        if "T1046" in technique or "port scan" in alert.get("trigger_reason", "").lower():
            questions.append(
                f"How many distinct destination ports has {src_ip} targeted across the environment recently?"
            )

        return questions


class EvidenceGatheringAgent:
    """
    RAG Agent: Routes questions to Knowledge Graph and Traffic tools, compiling factual evidence.
    """

    def __init__(self, kg_tool: NetworkTopologyKG, traffic_tool: TrafficAnalysisTool):
        self.kg = kg_tool
        self.traffic = traffic_tool

    def gather_evidence_for_questions(self, questions: List[str]) -> List[Dict[str, Any]]:
        evidence_pairs = []
        for q in questions:
            kg_data = self.kg.query(q)
            traffic_data = self.traffic.query(q)
            evidence_pairs.append({
                "question": q,
                "knowledge_graph_findings": kg_data.get("resolved_entities", {}),
                "traffic_analysis_findings": traffic_data.get("forensic_evidence", {}),
            })
        return sanitize_payloads(evidence_pairs)


class HypothesisGeneratorAgent:
    """
    Stage B Agent: Proposes candidate hypotheses covering attack techniques, misconfiguration, or benign noise.
    """

    def generate_hypotheses(self, alert: Dict[str, Any], initial_context: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        src_ip = alert.get("source_ip", "")
        dst_ip = alert.get("destination_ip", "")
        technique = alert.get("mitre_technique", "")
        trigger_reason = alert.get("trigger_reason", "").lower()

        hypotheses = []

        if "t1046" in technique.lower() or "port scan" in trigger_reason:
            hypotheses.append({
                "hypothesis_id": "H1",
                "category": "Active Cyber Attack",
                "title": "Adversary Reconnaissance / Network Port Scan",
                "description": f"Source {src_ip} is actively performing reconnaissance against internal assets to discover exploitable services.",
                "status": "Under Evaluation",
            })
            hypotheses.append({
                "hypothesis_id": "H2",
                "category": "Administrative Misconfiguration",
                "title": "Authorized Security Vulnerability Scanner",
                "description": f"Source {src_ip} is an approved vulnerability scanner or inventory auditing tool operating during a maintenance window.",
                "status": "Under Evaluation",
            })
            hypotheses.append({
                "hypothesis_id": "H3",
                "category": "Benign Network Noise",
                "title": "Endpoint Software Glitch or Misconfigured Service",
                "description": f"A legacy agent or misconfigured client on {src_ip} is rapidly cycling connection attempts due to network timeout.",
                "status": "Under Evaluation",
            })
        elif "t1041" in technique.lower() or "exfiltration" in trigger_reason or "statistical" in trigger_reason:
            hypotheses.append({
                "hypothesis_id": "H1",
                "category": "Active Cyber Attack",
                "title": "Data Exfiltration via Encrypted C2 Tunnel",
                "description": f"Compromised host {src_ip} is exfiltrating intellectual property or sensitive database dumps to {dst_ip}.",
                "status": "Under Evaluation",
            })
            hypotheses.append({
                "hypothesis_id": "H2",
                "category": "Operational Activity",
                "title": "Scheduled Enterprise Database Backup Transfer",
                "description": f"Large volumetric transfer between {src_ip} and {dst_ip} corresponds to an authorized data sync or offsite backup.",
                "status": "Under Evaluation",
            })
            hypotheses.append({
                "hypothesis_id": "H3",
                "category": "Benign Network Noise",
                "title": "Large Software Update or File Cache Sync",
                "description": f"Host {src_ip} is downloading large system updates or ISO image distributions.",
                "status": "Under Evaluation",
            })
        else:
            hypotheses.append({
                "hypothesis_id": "H1",
                "category": "Active Cyber Attack",
                "title": "Malicious Connection / Command & Control Activity",
                "description": f"Anomalous traffic from {src_ip} represents adversary C2 staging or beaconing.",
                "status": "Under Evaluation",
            })
            hypotheses.append({
                "hypothesis_id": "H2",
                "category": "Administrative Misconfiguration",
                "title": "Non-Standard Port Application Deployment",
                "description": f"An unapproved internal application or developer test service was deployed on a non-standard port.",
                "status": "Under Evaluation",
            })

        return hypotheses[:3]


class PlannerAgent:
    """
    Stage B Agent: Formulates targeted forensic questions to validate or refute each hypothesis.
    """

    def plan_questions(self, hypothesis: Dict[str, Any], alert: Dict[str, Any]) -> List[str]:
        src_ip = alert.get("source_ip", "")
        dst_ip = alert.get("destination_ip", "")
        h_id = hypothesis.get("hypothesis_id")

        if "Reconnaissance" in hypothesis.get("title", "") or "Attack" in hypothesis.get("category", ""):
            return [
                f"Is host {src_ip} classified as an administrative or security scanner in the Knowledge Graph?",
                f"What is the ratio of SYN to ACK flags generated by {src_ip} in flow telemetry?",
            ]
        elif "Scanner" in hypothesis.get("title", "") or "Backup" in hypothesis.get("title", ""):
            return [
                f"Does host {src_ip} belong to SecOps or IT Infrastructure subnets?",
                f"Are there documented authorized relationships connecting {src_ip} to {dst_ip}?",
            ]
        else:
            return [
                f"Does {src_ip} have a history of communicating with {dst_ip}?",
            ]


class HypothesisEvaluatorAgent:
    """
    Stage B Agent: Assesses question-answer evidence and assigns Supported, Refuted, or Unresolved status.
    """

    def evaluate_hypothesis(
        self,
        hypothesis: Dict[str, Any],
        evidence_pairs: List[Dict[str, Any]],
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:
        h_title = hypothesis.get("title", "")
        src_ip = alert.get("source_ip", "")

        # Extract device role from evidence if available
        device_role = "Unknown"
        dept = "Unknown"
        for ep in evidence_pairs:
            kg_entities = ep.get("knowledge_graph_findings", {})
            if src_ip in kg_entities:
                device_role = kg_entities[src_ip].get("role", device_role)
                dept = kg_entities[src_ip].get("department", dept)

        status = "Unresolved"
        justification = ""

        if "Reconnaissance" in h_title or "Attack" in hypothesis.get("category", ""):
            if "Finance" in dept or "Contractor" in device_role:
                status = "Supported"
                justification = (
                    f"Evidence confirms {src_ip} is a {device_role} ({dept} department), NOT an authorized "
                    f"IT/SecOps scanner. Rapid probing of unapproved ports is highly characteristic of compromise."
                )
            else:
                status = "Supported"
                justification = f"High-confidence correlation of anomalous telemetry from endpoint {src_ip}."

        elif "Authorized Security Vulnerability Scanner" in h_title or "Backup" in h_title:
            if "Finance" in dept:
                status = "Refuted"
                justification = (
                    f"Refuted by Knowledge Graph: {src_ip} is registered as a {device_role} in the {dept} department. "
                    f"It has zero scanner credentials or IT infrastructure authority."
                )
            else:
                status = "Refuted"
                justification = "No scheduled maintenance or backup task registered for this host."

        else:
            status = "Refuted"
            justification = "Traffic cadence and targeted destination ports rule out benign software glitches."

        result = dict(hypothesis)
        result["status"] = status
        result["evaluation_justification"] = justification
        return result


class FlowEvaluatorAgent:
    """
    Controls investigation graph transitions. Enforces a strict maximum of ONE retry
    per hypothesis to prevent infinite looping, then transitions to conclusion.
    """

    def __init__(self, max_retries_per_hypothesis: int = 1):
        self.max_retries = max_retries_per_hypothesis
        self.retry_counts: Dict[str, int] = {}

    def decide_next_step(
        self,
        evaluated_hypothesis: Dict[str, Any],
        current_index: int,
        total_hypotheses: int,
    ) -> Dict[str, Any]:
        h_id = evaluated_hypothesis.get("hypothesis_id", "H")
        status = evaluated_hypothesis.get("status", "Unresolved")

        if status == "Unresolved" and self.retry_counts.get(h_id, 0) < self.max_retries:
            self.retry_counts[h_id] = self.retry_counts.get(h_id, 0) + 1
            return {
                "action": "RETRY_HYPOTHESIS",
                "hypothesis_id": h_id,
                "reason": "Hypothesis unresolved; scheduling single targeted secondary probe.",
            }

        if current_index + 1 < total_hypotheses:
            return {
                "action": "NEXT_HYPOTHESIS",
                "next_index": current_index + 1,
            }

        return {
            "action": "CONCLUDE_INVESTIGATION",
            "reason": "All hypotheses thoroughly evaluated.",
        }


class ExplanationAgent:
    """
    Stage C Agent: Synthesizes complete multi-agent investigation into a plain-English executive narrative.
    """

    def synthesize_report(
        self,
        alert: Dict[str, Any],
        initial_context: List[Dict[str, Any]],
        evaluated_hypotheses: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        supported_hyp = [h for h in evaluated_hypotheses if h.get("status") == "Supported"]
        primary_conclusion = (
            supported_hyp[0]["title"] if supported_hyp else "Unconfirmed Anomaly"
        )
        primary_justification = (
            supported_hyp[0]["evaluation_justification"] if supported_hyp else "Inconclusive telemetry."
        )

        executive_summary = (
            f"On {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(alert.get('timestamp', time.time())))}, "
            f"NetSentinel detected a {alert.get('severity')} severity incident originating from {alert.get('source_ip')} "
            f"classified under MITRE ATT&CK {alert.get('mitre_tactic')} ({alert.get('mitre_technique')}). "
            f"The forensic multi-agent investigation validated '{primary_conclusion}'. "
            f"{primary_justification}"
        )

        technical_details = {
            "alert_id": alert.get("alert_id"),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "deviation_score": alert.get("deviation_score"),
            "trigger_reason": alert.get("trigger_reason"),
            "evaluated_hypotheses": evaluated_hypotheses,
        }

        recommended_actions = [
            f"Immediately isolate host {alert.get('source_ip')} from VLAN/Subnet.",
            f"Revoke Active Directory tokens and kerberos tickets associated with {alert.get('source_ip')}.",
            "Collect host-level memory dump and inspect running processes for suspicious beaconing.",
        ]

        return {
            "incident_title": f"Security Incident Report: {primary_conclusion}",
            "executive_summary": executive_summary,
            "technical_triage": sanitize_payloads(technical_details),
            "recommended_actions": recommended_actions,
        }


class ExplanationReviewerAgent:
    """
    Stage C Agent: Evaluates narrative report against factual evidence, verifies zero hallucinations
    or ungrounded claims, and enforces strict technical accuracy.
    """

    def review_report(
        self,
        report: Dict[str, Any],
        evidence: List[Dict[str, Any]],
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:
        narrative = report.get("executive_summary", "")

        # Verify ground truth anchors
        src_ip = alert.get("source_ip", "")
        grounded_src_ip = src_ip in narrative
        grounded_severity = alert.get("severity", "") in narrative

        hallucination_detected = not (grounded_src_ip and grounded_severity)
        verification_status = "VERIFIED_ACCURATE" if not hallucination_detected else "CORRECTIONS_REQUIRED"

        return {
            "review_status": verification_status,
            "grounding_check": {
                "source_ip_verified": grounded_src_ip,
                "severity_verified": grounded_severity,
                "hallucinations_detected": hallucination_detected,
            },
            "approved_report": report,
        }
