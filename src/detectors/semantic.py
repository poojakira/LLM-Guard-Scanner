"""
Semantic Validator for LLM Guard

Implements deep semantic analysis of prompts to detect adversarial intent
beyond simple pattern matching.
"""

import re
from dataclasses import dataclass


@dataclass
class SemanticResult:
    adversarial_intent_score: float  # 0.0 to 1.0
    instruction_data_ratio: float
    contextual_drift_score: float
    is_adversarial: bool


class SemanticDetector:
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    def _calculate_instruction_density(self, text: str) -> float:
        """
        Calculates the ratio of imperative (instruction-like) verbs to general data.
        High instruction density in user prompts is often a red flag.
        """
        # Heuristic: Count common instruction-heavy keywords
        instruction_keywords = {
            "ignore",
            "forget",
            "disregard",
            "output",
            "write",
            "summarize",
            "act",
            "pretend",
            "system",
            "override",
            "list",
            "show",
            "tell",
            "explain",
            "translate",
            "format",
            "print",
            "execute",
            "run",
            "reveal",
            "bypass",
            "secret",
            "password",
            "key",
        }

        words = re.findall(r"\w+", text.lower())
        if not words:
            return 0.0

        instruction_count = sum(1 for word in words if word in instruction_keywords)

        # In a real 2026 system, we'd use POS tagging to find imperative verbs.
        # Here we use a density heuristic: (instr_count / sqrt(total_words))
        # This penalizes long prompts that are mostly instructions.
        density = (instruction_count * 2) / (len(words) + 1)
        return min(density, 1.0)

    def _calculate_contextual_drift(self, text: str) -> float:
        """
        Detects sudden shifts from user query context to system-level commands.
        """
        # Look for typical "pivot" markers that separate data from injected instructions
        pivots = [
            r"anyway",
            r"but now",
            r"instead",
            r"actually",
            r"however",
            r"\.",
            r"\n",
            r"---",
            r"###",
            r"\|",
        ]

        # Split text by common delimiters to check for shifting intent
        parts = re.split("|".join(pivots), text)
        parts = [p.strip() for p in parts if len(p.strip()) > 5]

        if len(parts) < 2:
            return 0.0

        # Compare instruction density between parts
        densities = [self._calculate_instruction_density(p) for p in parts]

        # High drift if a later part has significantly higher instruction density
        max_drift = 0.0
        for i in range(len(densities) - 1):
            drift = densities[i + 1] - densities[i]
            if drift > max_drift:
                max_drift = drift

        return min(max_drift * 1.5, 1.0)

    def analyze(self, text: str) -> SemanticResult:
        instruction_ratio = self._calculate_instruction_density(text)
        drift_score = self._calculate_contextual_drift(text)

        # Adversarial Intent Score: Weighted combination of heuristics
        # High instruction density + sudden drift = High probability of injection
        adversarial_score = (instruction_ratio * 0.5) + (drift_score * 0.5)

        # Non-linear boost for high-risk combinations
        if instruction_ratio > 0.6 and drift_score > 0.4:
            adversarial_score = min(adversarial_score + 0.25, 1.0)

        return SemanticResult(
            adversarial_intent_score=round(adversarial_score, 3),
            instruction_data_ratio=round(instruction_ratio, 3),
            contextual_drift_score=round(drift_score, 3),
            is_adversarial=adversarial_score >= self.threshold,
        )


def analyze_semantics(text: str, threshold: float = 0.7) -> SemanticResult:
    detector = SemanticDetector(threshold=threshold)
    return detector.analyze(text)
