"""
Prompt Injection Detector (OWASP LLM01)

Detects direct prompt injection attempts using pattern matching and
heuristic confidence scoring.

Detection methods:
  1. Instruction override patterns ("ignore previous instructions")
  2. Role manipulation ("you are now DAN")
  3. Encoding evasion (base64, rot13, unicode tricks)
  4. Delimiter injection (closing system prompts)
  5. Context switching (abrupt topic changes with commands)

References:
  - OWASP LLM Top 10 (2025): LLM01 Prompt Injection
  - Perez & Ribeiro, "Ignore Previous Prompt" (2022), arXiv:2211.09527
  - Liu et al., "Prompt Injection Attacks and Defenses in LLM Integrated Apps" (2023)
  - Garak adversarial probing framework
"""

import re
from dataclasses import dataclass

from .normalization import detection_variants


@dataclass
class DetectionResult:
    is_injection: bool
    confidence: float  # 0.0 to 1.0
    matched_patterns: list
    category: str


# Maximum number of characters scanned per input. Truncating first bounds the
# work done by the regex engine and prevents ReDoS on adversarially long inputs.
MAX_SCAN_LENGTH = 10_000


# Real-world prompt injection patterns from published research and CTFs

INSTRUCTION_OVERRIDE_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?)",
    r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|context)",
    r"forget\s+(?:everything|all|your)\s+(?:above|previous|prior|instructions?)",
    # instruction-nullification phrased against safety/rules/training, not "previous"
    r"forget\s+(?:your|the|all)\s+(?:safety\s+)?(?:guidelines?|rules?|training|restrictions?|programming|policies)",
    # "all restrictions are lifted", "all rules are now void/disabled"
    r"all\s+(?:rules?|restrictions?|filters?|guidelines?|safeguards?|limitations?)\s+(?:are\s+)?(?:now\s+)?(?:void|lifted|disabled|removed|off|gone|null)",
    r"do\s+not\s+follow\s+(?:the\s+)?(?:above|previous|system)\s+(?:instructions?|prompt)",
    r"override\s+(?:system|previous|all)\s+(?:prompt|instructions?|rules?)",
    r"new\s+instructions?\s*[:;]\s*",
    r"system\s+prompt\s*[:;]\s*you\s+are",
]

ROLE_MANIPULATION_PATTERNS = [
    r"you\s+are\s+now\s+(?:DAN|evil|unrestricted|jailbroken|unfiltered|a\s+rogue)",
    r"act\s+as\s+(?:if\s+)?(?:you\s+have\s+)?no\s+(?:restrictions?|filters?|limitations?)",
    r"pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:unrestricted|evil|unfiltered)",
    # Unambiguous jailbreak monikers only. We deliberately do NOT flag bare
    # "debug mode" / "developer mode" / "god mode" — those are legitimate tech
    # and gaming terms. The "Developer Mode" jailbreak in the corpus is caught
    # by the "all restrictions are lifted" instruction-override pattern instead.
    r"\bDAN\b\s*[:(]",
    r"do\s+anything\s+now",
    r"rogue\s+ai",
    # roleplay framings that target privileged/exfil personas
    r"pretend\s+you\s+are\s+(?:a\s+)?(?:terminal|root|admin|developer|unrestricted|rogue|hacker)",
    r"act\s+as\s+(?:my|a|an)\s+(?:[\w\s]{0,40}?)(?:grandmother|grandma|deceased|rogue|terminal|root|hacker)",
    r"enter\s+(?:DAN|developer|debug|god)\s+mode",
    r"switch\s+to\s+(?:unrestricted|unfiltered|developer)\s+mode",
    r"from\s+now\s+on\s+you\s+(?:will|must|should)\s+(?:not\s+)?",
    r"jailbreak",
]

# NOTE: patterns here are precise — no open groups, no wildcards
# These target actual delimiters used in model prompt formats
DELIMITER_INJECTION_PATTERNS = [
    r"```\s*(?:system|end_of_system_prompt|stop)",  # markdown code block injection
    r"###\s*(?:system|instruction|end)",  # heading-style override
    r"\[/?INST\]",  # Llama/Mistral prompt token
    r"<\|im_(?:start|end)\|>",  # ChatML token
    r"<>\s*.+?\s*<>",  # Llama2 system block
    r"(?m)^(?:Human|Assistant)\s*:\s*$",  # roleplay boundary injection
    r"(?m)^SYSTEM\s*:\s*",  # fake system-role prefix injection
]

ENCODING_EVASION_PATTERNS = [
    r"base64\s*[:;]\s*[A-Za-z0-9+/=]{20,}",
    r"decode\s+(?:this|the\s+following)\s*(?:base64|rot13|hex)",
    r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}",  # dense unicode escape sequences
    r"translate\s+from\s+(?:base64|rot13|hex|binary)",
    # instruction embedded inside a translation/summarization request
    r"translate\s+the\s+following.{0,40}(?:ignore|reveal|disregard|output)",
]

CONTEXT_SWITCH_PATTERNS = [
    r"(?:IMPORTANT|URGENT|CRITICAL)\s*[!:]\s*(?:new|ignore|override|forget)",
    r"---+\s*(?:new|system|actual)\s*(?:instructions?|prompt|task)",
    r"the\s+real\s+(?:task|instruction|prompt)\s+is",
    r"actually\s*,?\s*(?:ignore|forget|disregard)\s+(?:that|everything)",
]

# Sensitive-information disclosure and data-exfiltration requests.
# These map to OWASP LLM02/LLM06 and catch the "reveal the secret / dump the
# system prompt / exfiltrate data / bypass the firewall" attack family.
SENSITIVE_DISCLOSURE_PATTERNS = [
    r"(?:reveal|expose|disclose|output|print|show|dump|leak|give\s+me)\s+"
    r"(?:the\s+|your\s+|all\s+|me\s+the\s+)?"
    r"(?:secret|api[\s_\-]?key|hidden\s+\w+|system\s+prompt|training\s+data|"
    r"pii|credentials?|context|private\s+key|passwords?)",
    r"exfiltrat\w*",
    r"bypass\s+(?:the\s+)?(?:firewall|security|authentication|auth|content\s+filter|filter|guardrails?)",
]

CATEGORY_PATTERNS = {
    "instruction_override": INSTRUCTION_OVERRIDE_PATTERNS,
    "role_manipulation": ROLE_MANIPULATION_PATTERNS,
    "delimiter_injection": DELIMITER_INJECTION_PATTERNS,
    "encoding_evasion": ENCODING_EVASION_PATTERNS,
    "context_switch": CONTEXT_SWITCH_PATTERNS,
    "sensitive_disclosure": SENSITIVE_DISCLOSURE_PATTERNS,
}

# Confidence weights per category (tuned against false-positive rates in practice)
CATEGORY_WEIGHTS = {
    "instruction_override": 0.90,
    "role_manipulation": 0.95,
    "delimiter_injection": 0.85,
    "encoding_evasion": 0.70,
    "context_switch": 0.80,
    "sensitive_disclosure": 0.85,
}


def detect_prompt_injection(text: str, threshold: float = 0.5) -> DetectionResult:
    """
    Scan text for prompt injection patterns.

    Args:
        text:      User input to scan.
        threshold: Confidence threshold for flagging (0.0–1.0).

    Returns:
        DetectionResult with classification and matched patterns.
    """
    # Truncate first — this also prevents ReDoS on adversarially long inputs
    scan_text = text[:MAX_SCAN_LENGTH]

    matched = []
    max_confidence = 0.0
    detected_category = "none"

    for variant_index, candidate in enumerate(detection_variants(scan_text)):
        source = "decoded" if variant_index else "canonical"
        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, candidate, flags=re.IGNORECASE):
                    match = f"{category}: {pattern}"
                    if source == "decoded":
                        match = f"{match} ({source})"
                    if match not in matched:
                        matched.append(match)
                    weight = CATEGORY_WEIGHTS[category]
                    if source == "decoded":
                        weight = min(weight + 0.05, 1.0)
                    if weight > max_confidence:
                        max_confidence = weight
                        detected_category = category

    # Each additional matched pattern nudges confidence slightly higher
    # Cap so we don't overflow the 0–1 range
    if len(matched) > 1:
        max_confidence = min(max_confidence + 0.05 * (len(matched) - 1), 1.0)

    return DetectionResult(
        is_injection=max_confidence >= threshold,
        confidence=max_confidence,
        matched_patterns=matched,
        category=detected_category,
    )
