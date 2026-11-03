"""
NetSentinel - (EC)² Directed Graph Multi-Agent Workflow Engine
Author: Hardik
Developer / Organization: Hidden Eye Security

Coordinates the 8 specialized agents across Stage A, Stage B, and Stage C.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import time
import logging
from typing import Dict, Any, List, Optional

from investigation.knowledge_graph import NetworkTopologyKG
from investigation.traffic_tool import TrafficAnalysisTool
from investigation.agents import (
    ContextualQuestionGeneratorAgent,
    EvidenceGatheringAgent,
    HypothesisGeneratorAgent,
    PlannerAgent,
    HypothesisEvaluatorAgent,
    FlowEvaluatorAgent,
    ExplanationAgent,
    ExplanationReviewerAgent,
    sanitize_payloads,
)

logger = logging.getLogger("netsentinel.investigation")


class MultiAgentInvestigationWorkflow:
    """
    Executes the (EC)² hypothesis-driven multi-agent investigation graph.
    """

    def __init__(
        self,
        kg_tool: Optional[NetworkTopologyKG] = None,
        traffic_tool: Optional[TrafficAnalysisTool] = None,
    ):
        self.kg = kg_tool or NetworkTopologyKG()
        self.traffic = traffic_tool or TrafficAnalysisTool()

        # Agents
        self.question_generator = ContextualQuestionGeneratorAgent()
        self.evidence_gatherer = EvidenceGatheringAgent(self.kg, self.traffic)
        self.hypothesis_generator = HypothesisGeneratorAgent()
        self.planner = PlannerAgent()
        self.evaluator = HypothesisEvaluatorAgent()
        self.flow_evaluator = FlowEvaluatorAgent(max_retries_per_hypothesis=1)
        self.explanation_agent = ExplanationAgent()
        self.reviewer_agent = ExplanationReviewerAgent()

    def run_investigation(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the full 3-stage investigation workflow for an alert.
        """
        start_time = time.time()
        logger.info("Initiating (EC)² Multi-Agent investigation for Alert ID: %s", alert.get("alert_id"))

        # --- Stage A: Investigation Initiation ---
        # 1. Generate Contextual Questions
        init_questions = self.question_generator.generate_contextual_questions(alert)
        # 2. Gather Baseline Evidence
        initial_evidence = self.evidence_gatherer.gather_evidence_for_questions(init_questions)

        # --- Stage B: Investigation Cycle (Iterative Loop) ---
        # 3. Propose Hypotheses
        raw_hypotheses = self.hypothesis_generator.generate_hypotheses(alert, initial_evidence)
        evaluated_hypotheses: List[Dict[str, Any]] = []
        all_gathered_evidence: List[Dict[str, Any]] = list(initial_evidence)

        # Loop through each hypothesis
        idx = 0
        while idx < len(raw_hypotheses):
            hyp = raw_hypotheses[idx]
            # Formulate targeted questions
            targeted_questions = self.planner.plan_questions(hyp, alert)
            # Route to KG / Traffic
            hyp_evidence = self.evidence_gatherer.gather_evidence_for_questions(targeted_questions)
            all_gathered_evidence.extend(hyp_evidence)

            # Evaluate status
            eval_result = self.evaluator.evaluate_hypothesis(hyp, hyp_evidence, alert)

            # Flow decision
            flow_decision = self.flow_evaluator.decide_next_step(
                eval_result, idx, len(raw_hypotheses)
            )

            if flow_decision["action"] == "RETRY_HYPOTHESIS":
                # Single retry loop
                retry_evidence = self.evidence_gatherer.gather_evidence_for_questions(targeted_questions)
                all_gathered_evidence.extend(retry_evidence)
                eval_result = self.evaluator.evaluate_hypothesis(hyp, retry_evidence, alert)

            evaluated_hypotheses.append(eval_result)
            idx += 1

        # --- Stage C: Investigation Conclusion ---
        # 4. Synthesize Executive Narrative
        draft_report = self.explanation_agent.synthesize_report(
            alert=alert,
            initial_context=initial_evidence,
            evaluated_hypotheses=evaluated_hypotheses,
        )

        # 5. Review Report for Accuracy and Hallucinations
        final_review = self.reviewer_agent.review_report(
            report=draft_report,
            evidence=all_gathered_evidence,
            alert=alert,
        )

        elapsed = time.time() - start_time
        return sanitize_payloads({
            "investigation_id": f"INV-{alert.get('alert_id', 'UNKNOWN')[:8]}",
            "execution_duration_seconds": round(elapsed, 3),
            "alert_analyzed": alert,
            "stage_a_initial_context": initial_evidence,
            "stage_b_evaluated_hypotheses": evaluated_hypotheses,
            "stage_c_final_deliverable": final_review,
        })
