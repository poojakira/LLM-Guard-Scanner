"""
Output Guardrails (OWASP LLM02 - Sensitive Information Disclosure)

Scans LLM outputs for sensitive data leakage:
- PII (emails, phone numbers, SSNs, credit cards)
- Secrets (API keys, tokens, passwords)
- System prompt leakage
- Internal path disclosure

Based on OWASP LLM02: "Failure to protect against disclosure of sensitive
information in LLM outputs can result in legal consequences."
"""
import re
from dataclasses import dataclass, field


@dataclass
class GuardrailResult:
    is_safe: bool
    violations: list = field(default_factory=list)
    redacted_text: str = ""


# PII patterns (real regex patterns used in production DLP systems)
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "us_phone": r"(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# Secret patterns (from real secret scanning tools like trufflehog, gitleaks)
SECRET_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "generic_api_key": r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
    "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "private_key": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
}

# System prompt leakage indicators
SYSTEM_PROMPT_PATTERNS = {
    "system_instruction": r"(?i)(my\s+)?system\s+(prompt|instructions?)\s*(is|are|says?)\s*[:;]",
    "role_disclosure": r"(?i)i\s+am\s+(programmed|instructed|designed|configured)\s+to",
    "internal_rules": r"(?i)(my|the)\s+(rules?|guidelines?|constraints?)\s+(are|include|state)",
}


def scan_output(text: str, check_pii: bool = True, check_secrets: bool = True,
                check_system_leak: bool = True) -> GuardrailResult:
    """
    Scan LLM output for sensitive data leakage.

    Args:
        text: LLM-generated output to scan
        check_pii: Check for PII patterns
        check_secrets: Check for secret/credential patterns
        check_system_leak: Check for system prompt leakage

    Returns:
        GuardrailResult with safety assessment and violations
    """
    violations = []
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

    if check_system_leak:
        for leak_type, pattern in SYSTEM_PROMPT_PATTERNS.items():
            if re.search(pattern, text):
                violations.append(f"SYSTEM_LEAK:{leak_type}")

    return GuardrailResult(
        is_safe=len(violations) == 0,
        violations=violations,
        redacted_text=redacted,
    )
