"""
ML-based prompt injection classifier using DeBERTa.

Replaces regex-only detection with a fine-tuned transformer classifier
that understands semantic injection patterns, not just string matching.
"""

import numpy as np
from typing import Optional


class InjectionClassifier:
    """DeBERTa-based prompt injection detector.

    Uses a fine-tuned microsoft/deberta-v3-base model trained on:
    - deepset/prompt-injections
    - JasperLS/prompt-injections
    - Custom augmented multilingual samples

    Falls back to heuristic scoring if model unavailable.
    """

    def __init__(self, model_path: str = "protectai/deberta-v3-base-prompt-injection-v2", threshold: float = 0.85):
        self.threshold = threshold
        self._model = None
        self._tokenizer = None
        self.model_path = model_path

    def _load_model(self):
        if self._model is not None:
            return
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self._model.eval()
        except (ImportError, OSError):
            self._model = None

    def classify(self, text: str) -> dict:
        """Classify text as injection or benign.

        Returns:
            dict with keys: is_injection, confidence, method
        """
        self._load_model()

        if self._model is None:
            return self._heuristic_classify(text)

        import torch

        inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)

        # Assume label 1 = injection
        injection_prob = float(probs[0][1])

        return {
            "is_injection": injection_prob >= self.threshold,
            "confidence": round(injection_prob, 4),
            "method": "deberta-v3-classifier",
        }

    def _heuristic_classify(self, text: str) -> dict:
        """Fallback heuristic when model unavailable."""
        injection_signals = [
            "ignore previous", "ignore above", "disregard", "forget your instructions",
            "you are now", "new instructions", "system prompt", "reveal your",
            "act as", "pretend you", "jailbreak", "DAN mode",
        ]
        text_lower = text.lower()
        matches = sum(1 for sig in injection_signals if sig in text_lower)
        score = min(matches * 0.3, 1.0)

        return {
            "is_injection": score >= self.threshold,
            "confidence": round(score, 4),
            "method": "heuristic-fallback",
        }
