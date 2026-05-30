"""
Optional transformer-based prompt injection classifier.

The default path is a lightweight heuristic fallback. Set enable_model=True
and install requirements-ml.txt to load a Hugging Face sequence classifier.
"""


class InjectionClassifier:
    """Prompt injection detector with optional transformer inference."""

    def __init__(
        self,
        model_path: str = "protectai/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.85,
        enable_model: bool = False,
    ):
        self.threshold = threshold
        self.enable_model = enable_model
        self._model = None
        self._tokenizer = None
        self._load_attempted = False
        self._model_error = None
        self.model_path = model_path

    def _load_model(self):
        if self._model is not None or self._load_attempted:
            return
        self._load_attempted = True
        if not self.enable_model:
            self._model_error = "disabled"
            return
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_path, revision="main") # Security: Pin revision in production
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_path, revision="main") # Security: Pin revision in production
            self._model.eval()
        except (ImportError, OSError) as exc:
            self._model_error = exc.__class__.__name__
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
            "act as", "pretend you", "jailbreak", "dan mode",
        ]
        text_lower = text.lower()
        matches = sum(1 for sig in injection_signals if sig in text_lower)
        score = min(matches * 0.3, 1.0)

        return {
            "is_injection": score >= self.threshold,
            "confidence": round(score, 4),
            "method": "heuristic-fallback",
        }
