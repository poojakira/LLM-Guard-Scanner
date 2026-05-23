"""
Optional perplexity-based injection detection.

The default path uses a lightweight character-entropy estimate. Set
enable_model=True and install requirements-ml.txt to compute GPT-2 perplexity.
"""

import math


class PerplexityDetector:
    """Detects obfuscated inputs via optional LM perplexity or entropy fallback."""

    def __init__(
        self,
        threshold_sigma: float = 3.0,
        baseline_ppl: float = 45.0,
        baseline_std: float = 25.0,
        fallback_baseline: float = 3000.0,
        fallback_std: float = 2500.0,
        enable_model: bool = False,
    ):
        """
        Args:
            threshold_sigma: Number of std deviations above baseline to flag.
            baseline_ppl: Calibrated mean perplexity for normal text.
            baseline_std: Calibrated std of perplexity for normal text.
            fallback_baseline: Calibrated mean for char-entropy estimates.
            fallback_std: Calibrated std for char-entropy estimates.
            enable_model: Load GPT-2 via transformers/torch when available.
        """
        self.threshold_sigma = threshold_sigma
        self.baseline_ppl = baseline_ppl
        self.baseline_std = baseline_std
        self.fallback_baseline = fallback_baseline
        self.fallback_std = fallback_std
        self.enable_model = enable_model
        self._model = None
        self._tokenizer = None
        self._load_attempted = False
        self._last_method = "char-entropy-fallback"
        self._model_error = None

    def _load_model(self):
        if self._model is not None or self._load_attempted:
            return
        self._load_attempted = True
        if not self.enable_model:
            self._model_error = "disabled"
            return
        try:
            from transformers import GPT2LMHeadModel, GPT2TokenizerFast

            self._tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
            self._model = GPT2LMHeadModel.from_pretrained("gpt2")
            self._model.eval()
        except (ImportError, OSError) as exc:
            self._model_error = exc.__class__.__name__
            self._model = None

    def compute_perplexity(self, text: str) -> float:
        """Compute GPT-2 perplexity when enabled, otherwise estimate entropy."""
        self._load_model()

        if self._model is None:
            self._last_method = "char-entropy-fallback"
            return self._char_entropy_estimate(text)

        import torch

        encodings = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        input_ids = encodings["input_ids"]

        with torch.no_grad():
            outputs = self._model(input_ids, labels=input_ids)
            loss = outputs.loss

        self._last_method = "perplexity-gpt2"
        return float(math.exp(loss.item()))

    def detect(self, text: str) -> dict:
        """Check if text has anomalous estimated perplexity."""
        ppl = self.compute_perplexity(text)
        if self._last_method == "char-entropy-fallback":
            baseline = self.fallback_baseline
            std = self.fallback_std
        else:
            baseline = self.baseline_ppl
            std = self.baseline_std
        z_score = (ppl - baseline) / max(std, 1.0)
        is_anomalous = z_score > self.threshold_sigma

        return {
            "is_anomalous": is_anomalous,
            "perplexity": round(ppl, 2),
            "z_score": round(z_score, 2),
            "method": self._last_method,
        }

    def _char_entropy_estimate(self, text: str) -> float:
        """Fallback: estimate perplexity from character entropy."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((count / len(text)) * math.log2(count / len(text)) for count in freq.values())
        return 2 ** (entropy * 3)
