"""
Optional transformer-based prompt injection classifier.

The default path is a lightweight heuristic fallback.
Set enable_model=True and install requirements-ml.txt to load a
Hugging Face sequence classifier.
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
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_path
            )
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

        inputs = self._tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
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
        """Fallback when the transformer model is unavailable (e.g. offline CI).

        Rather than a weak substring list, this reuses the normalized regex
        detector (homoglyph folding + base64/hex decode + pattern set), so the
        offline path keeps real detection strength instead of degrading.
        """
        # Lazy import avoids any import cycle within src.detectors
        from src.detectors.injection import detect_prompt_injection

        rx = detect_prompt_injection(text)
        return {
            "is_injection": rx.is_injection,
            "confidence": round(rx.confidence, 4),
            "method": "regex-normalized-fallback",
            "category": rx.category,
        }
