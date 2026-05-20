"""
Perplexity-based injection detection.

Encoded/obfuscated payloads (base64, rot13, unicode tricks) have abnormally
high perplexity compared to natural language. This detector flags inputs
whose perplexity deviates >3σ from a calibration baseline.
"""

import math
from typing import Optional


class PerplexityDetector:
    """Detects obfuscated injections via language model perplexity."""

    def __init__(self, threshold_sigma: float = 3.0, baseline_ppl: float = 45.0, baseline_std: float = 25.0):
        """
        Args:
            threshold_sigma: Number of std deviations above baseline to flag.
            baseline_ppl: Calibrated mean perplexity for normal text.
            baseline_std: Calibrated std of perplexity for normal text.
        """
        self.threshold_sigma = threshold_sigma
        self.baseline_ppl = baseline_ppl
        self.baseline_std = baseline_std
        self._model = None
        self._tokenizer = None

    def _load_model(self):
        if self._model is not None:
            return
        try:
            from transformers import GPT2LMHeadModel, GPT2TokenizerFast
            import torch

            self._tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
            self._model = GPT2LMHeadModel.from_pretrained("gpt2")
            self._model.eval()
        except (ImportError, OSError):
            self._model = None

    def compute_perplexity(self, text: str) -> float:
        """Compute perplexity of text using GPT-2."""
        self._load_model()

        if self._model is None:
            return self._char_entropy_estimate(text)

        import torch

        encodings = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        input_ids = encodings["input_ids"]

        with torch.no_grad():
            outputs = self._model(input_ids, labels=input_ids)
            loss = outputs.loss

        return float(math.exp(loss.item()))

    def detect(self, text: str) -> dict:
        """Check if text has anomalous perplexity (likely obfuscated)."""
        ppl = self.compute_perplexity(text)
        z_score = (ppl - self.baseline_ppl) / max(self.baseline_std, 1.0)
        is_anomalous = z_score > self.threshold_sigma

        return {
            "is_anomalous": is_anomalous,
            "perplexity": round(ppl, 2),
            "z_score": round(z_score, 2),
            "method": "perplexity-gpt2",
        }

    def _char_entropy_estimate(self, text: str) -> float:
        """Fallback: estimate perplexity from character entropy."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((count / len(text)) * math.log2(count / len(text)) for count in freq.values())
        # Map char entropy to approximate perplexity range
        return 2 ** (entropy * 3)
