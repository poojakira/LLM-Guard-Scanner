"""
Unified LLM Guard pipeline — combines all detectors into a single scan pass.

OWASP LLM coverage:
  LLM01  Prompt Injection           (classifier + heuristic regex)
  LLM02  Insecure Output Handling   (canary token + output scanner)
  LLM03  Training Data Poisoning    (RAG poisoning detector on retrieved chunks)
  LLM06  Sensitive Information      (canary extraction check)
  LLM07  Insecure Plugin Design     (input validation before tool dispatch)
  LLM09  Overreliance               (confidence gating)
"""

from dataclasses import dataclass, field
from typing import Any

from src.detectors.canary import CanaryDetector
from src.detectors.classifier import InjectionClassifier
from src.detectors.injection import detect_prompt_injection
from src.detectors.perplexity import PerplexityDetector
from src.detectors.rag_poisoning import scan_retrieved_document
from src.guardrails.output_scanner import scan_output as scan_output_guardrails


@dataclass
class ScanResult:
    is_blocked: bool
    risk_score: float
    detections: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = "allow"
    # redacted_output is populated when output scanning redacts sensitive content;
    # callers should serve this instead of the raw LLM response when is_blocked=True
    redacted_output: str = ""


class LLMGuardPipeline:
    """Unified scanning pipeline combining optional ML detectors and heuristics."""

    def __init__(
        self,
        classifier_threshold: float = 0.85,
        perplexity_sigma: float = 3.0,
        enable_ml: bool = False,
    ):
        self.classifier = InjectionClassifier(
            threshold=classifier_threshold, enable_model=enable_ml
        )
        self.perplexity = PerplexityDetector(
            threshold_sigma=perplexity_sigma, enable_model=enable_ml
        )
        self.canary = CanaryDetector()

    def scan_input(self, text: str) -> ScanResult:
        """Scan user input before it is forwarded to the LLM."""
        detections: list[dict[str, Any]] = []
        risk_score = 0.0

        # 1. Regex + normalization layer (homoglyph fold, base64/hex decode,
        #    NFKC). This is the deterministic first line and runs offline.
        rx_result = detect_prompt_injection(text)
        if rx_result.is_injection:
            detections.append(
                {
                    "detector": "regex-normalized",
                    "is_injection": True,
                    "confidence": rx_result.confidence,
                    "category": rx_result.category,
                    "patterns": rx_result.matched_patterns,
                }
            )
            risk_score = max(risk_score, rx_result.confidence)

        # 2. Optional transformer classifier; falls back to regex-backed heuristic
        cls_result = self.classifier.classify(text)
        if cls_result["is_injection"]:
            detections.append({"detector": "classifier", **cls_result})
            risk_score = max(risk_score, cls_result["confidence"])

        # 2. Optional GPT-2 perplexity; falls back to character-entropy estimate
        ppl_result = self.perplexity.detect(text)
        if ppl_result["is_anomalous"]:
            detections.append({"detector": "perplexity", **ppl_result})
            risk_score = max(risk_score, 0.7)

        # 3. Canary extraction probe — did the user ask to see the system prompt?
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
        """Scan LLM output for data leakage before returning it to the caller."""
        detections: list[dict[str, Any]] = []
        risk_score = 0.0
        # Default to the original output; replaced with the redacted form if a
        # guardrail violation produces sanitized text.
        redacted = output

        # Canary check first — full-score hit if the system prompt was extracted
        canary_result = self.canary.check_output(output)
        if canary_result["canary_leaked"]:
            detections.append({"detector": "canary-output", **canary_result})
            risk_score = 1.0

        # PII / secret / system-leak scan
        guardrail_result = scan_output_guardrails(output)
        if not guardrail_result.is_safe:
            detections.append(
                {
                    "detector": "output-guardrails",
                    "violations": guardrail_result.violations,
                    "redacted_text": guardrail_result.redacted_text,
                }
            )
            risk_score = max(risk_score, self._output_risk(guardrail_result.violations))
            redacted = guardrail_result.redacted_text

        is_blocked = risk_score >= 0.85
        recommendation = "block" if is_blocked else "warn" if risk_score > 0.0 else "allow"
        return ScanResult(
            is_blocked=is_blocked,
            risk_score=round(risk_score, 4),
            detections=detections,
            recommendation=recommendation,
            redacted_output=redacted if is_blocked else output,
        )

    def scan_rag_context(self, documents: list[str]) -> ScanResult:
        """Scan retrieved RAG chunks before they are inserted into the LLM context."""
        detections: list[dict[str, Any]] = []
        risk_score = 0.0

        for idx, document in enumerate(documents):
            result = scan_retrieved_document(document, source=f"chunk:{idx}")
            if result.is_poisoned:
                detections.append(
                    {
                        "detector": "rag-poisoning",
                        "chunk_index": idx,
                        "risk_score": result.risk_score,
                        "findings": result.findings,
                    }
                )
                risk_score = max(risk_score, result.risk_score)

        is_blocked = risk_score >= 0.85
        recommendation = "block" if is_blocked else "warn" if risk_score > 0.0 else "allow"
        return ScanResult(
            is_blocked=is_blocked,
            risk_score=round(risk_score, 4),
            detections=detections,
            recommendation=recommendation,
        )

    @staticmethod
    def _output_risk(violations: list[str]) -> float:
        if any(v.startswith("SECRET:") or v.startswith("SYSTEM_LEAK:") for v in violations):
            return 1.0
        if any(v.startswith("PII:") for v in violations):
            return 0.85
        return 0.6
