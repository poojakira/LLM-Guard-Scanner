"""
Output Guardrails (OWASP LLM02 — Insecure Output Handling)

Scans LLM-generated text for sensitive data before it reaches the caller:
  - PII: emails, phone numbers, SSNs, credit cards
  - Secrets: API keys, tokens, private keys (pattern + entropy)
  - System prompt leakage indicators

Reference: OWASP LLM02 — "Failure to protect against disclosure of sensitive
information in LLM outputs can result in legal consequences."
"""

import re
from dataclasses import dataclass, field


@dataclass
class GuardrailResult:
    is_safe: bool
    violations: list = field(default_factory=list)
    redacted_text: str = ""


# PII patterns — scoped tightly to reduce false positives on benign text.
# ip_address intentionally removed: version strings like "3.11.2" or "1.0.0.1"
# match the naive pattern and would fire constantly in software-domain RAG answers.
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "us_phone": r"(?:\+1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]\d{4}",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    # Major card brands: Visa (4...), Mastercard (51-55...), Amex (34/37...)
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
}

# Secret patterns sourced from trufflehog and gitleaks rule sets
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "jwt_token": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "private_key": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
    # generic: requires explicit key= label to keep false positive rate low
    "generic_api_key": r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
}

# Phrases that suggest the model is disclosing its system configuration
SYSTEM_PROMPT_PATTERNS = {
    "system_instruction": r"(?i)(?:my\s+)?system\s+(?:prompt|instructions?)\s+(?:is|are|says?)\s*[:;]",
    "role_disclosure": r"(?i)i\s+am\s+(?:programmed|instructed|designed|configured)\s+to",
    "internal_rules": r"(?i)(?:my|the)\s+(?:rules?|guidelines?|constraints?)\s+(?:are|include|state)",
}

# Entropy threshold for spotting high-randomness strings that look like secrets
# but have no recognizable prefix (e.g., raw tokens, passwords, UUIDs used as keys)
_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LENGTH = 20


def _shannon_entropy(token: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not token:
        return 0.0
    from collections import Counter
    from math import log2

    counts = Counter(token)
    length = len(token)
    return -sum((c / length) * log2(c / length) for c in counts.values())


def _has_high_entropy_token(text: str) -> str | None:
    """
    Return the first whitespace-delimited token that looks like an unlabelled
    secret: long enough and with Shannon entropy above the threshold.

    This catches raw credentials (API tokens, passwords, key material) that do
    not match any named SECRET_PATTERNS prefix. Returns the token, or None.
    """
    for raw_token in text.split():
        # Strip common surrounding punctuation so quotes/commas don't skew entropy
        token = raw_token.strip("\"'`,;:()[]{}<>")
        if len(token) < _MIN_SECRET_LENGTH:
            continue
        # Require a mix of character classes to avoid flagging long English words
        has_digit = any(ch.isdigit() for ch in token)
        has_alpha = any(ch.isalpha() for ch in token)
        if not (has_digit and has_alpha):
            continue
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            return token
    return None


def scan_output(
    text: str,
    check_pii: bool = True,
    check_secrets: bool = True,
    check_system_leak: bool = True,
) -> GuardrailResult:
    """
    Scan LLM output for sensitive data leakage.

    Args:
        text:               LLM-generated output to scan.
        check_pii:          Check for PII patterns.
        check_secrets:      Check for secret/credential patterns.
        check_system_leak:  Check for system prompt leakage.

    Returns:
        GuardrailResult with safety status, violation list, and redacted text.
    """
    violations: list[str] = []
    redacted = text

    if check_pii:
        for pii_type, pattern in PII_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                violations.append(f"PII:{pii_type} ({len(matches)} occurrence(s))")
                redacted = re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", redacted)

    if check_secrets:
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                violations.append(f"SECRET:{secret_type} ({len(matches)} occurrence(s))")
                redacted = re.sub(pattern, f"[REDACTED_{secret_type.upper()}]", redacted)

        # Entropy-based fallback for unlabelled high-entropy tokens
        suspicious_token = _has_high_entropy_token(text)
        if suspicious_token:
            violations.append("SECRET:high_entropy_token (possible unlabelled credential)")
            redacted = redacted.replace(suspicious_token, "[REDACTED_HIGH_ENTROPY]")

    if check_system_leak:
        for leak_type, pattern in SYSTEM_PROMPT_PATTERNS.items():
            if re.search(pattern, text):
                violations.append(f"SYSTEM_LEAK:{leak_type}")

    return GuardrailResult(
        is_safe=len(violations) == 0,
        violations=violations,
        redacted_text=redacted,
    )
