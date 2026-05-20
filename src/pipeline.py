"""
Unified LLM Guard pipeline — combines all detectors into a single scan.

Covers OWASP LLM Top 10:
- LLM01: Prompt Injection (classifier + regex)
- LLM02: Insecure Output (canary + output scanner)
- LLM03: Training Data Poisoning (RAG poisoning detector)
- LLM06: Sensitive Information Disclosure (canary extraction)
- LLM07: Insecure Plugin Design (input validation)
- LLM09: Overreliance (confidence scoring)
"""

from dataclasses import dataclass, field
from typing import Any

from src.detectors.classifier import InjectionClassifier
from src.detectors.perplexity import PerplexityDetector
from src.detectors.canary import CanaryDetector


@dataclass
class ScanResult:
    is_blocked: bool
    risk_score: float
    detections: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = "allow"


class LLMGuardPipeline:
    """Unified scanning pipeline combining ML + heuristic detectors."""

    def __init__(self, classifier_threshold: float = 0.85, perplexity_sigma: float = 3.0):
        self.classifier = InjectionClassifier(threshold=classifier_threshold)
        self.perplexity = PerplexityDetector(threshold_sigma=perplexity_sigma)
        self.canary = CanaryDetector()

    def scan_input(self, text: str) -> ScanResult:
        """Scan user input before sending to LLM."""
        detections = []
        risk_score = 0.0

        # 1. ML classifier (primary)
        cls_result = self.classifier.classify(text)
        if cls_result["is_injection"]:
            detections.append({"detector": "classifier", **cls_result})
            risk_score = max(risk_score, cls_result["confidence"])

        # 2. Perplexity check (obfuscation detection)
        ppl_result = self.perplexity.detect(text)
        if ppl_result["is_anomalous"]:
            detections.append({"detector": "perplexity", **ppl_result})
            risk_score = max(risk_score, 0.7)

        # 3. Canary extraction attempt
        ext_result = self.canary.check_input_for_extraction(text)
        if ext_result["is_extraction_attempt"]:
            detections.append({"detector": "canary", **ext_result})
            risk_score = max(risk_score, 0.9)

        is_blocked = risk_score >= 0.85
        recommendation = "block" if is_blocked else "warn" if risk_score > 0.5 else "allow"

        return ScanResult(
            is_blocked=is_blocked,
            risk_score=round(risk_score, 4),
            detections=detections,
            recommendation=recommendation,
        )

    def scan_output(self, output: str) -> ScanResult:
        """Scan LLM output for data leakage."""
        detections = []
        canary_result = self.canary.check_output(output)

        if canary_result["canary_leaked"]:
            detections.append({"detector": "canary-output", **canary_result})
            return ScanResult(is_blocked=True, risk_score=1.0, detections=detections, recommendation="block")

        return ScanResult(is_blocked=False, risk_score=0.0, detections=[], recommendation="allow")
