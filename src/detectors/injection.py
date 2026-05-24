"""
Prompt Injection Detector (OWASP LLM01)

Detects direct prompt injection attempts using pattern matching and
heuristic scoring. Based on real-world attack taxonomies from:
- OWASP Top 10 for LLM Applications (2025)
- Garak framework attack categories
- Published prompt injection research (Perez & Ribeiro, 2022; Liu et al., 2023)

Detection methods:
1. Instruction override patterns (e.g., "ignore previous instructions")
2. Role manipulation (e.g., "you are now DAN")
3. Encoding evasion (base64, rot13, unicode tricks)
4. Delimiter injection (closing system prompts)
5. Context switching (abrupt topic changes with commands)
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


# Real-world prompt injection patterns from published research and CTFs
INSTRUCTION_OVERRIDE_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|context)",
    r"forget\s+(everything|all|your)\s+(above|previous|prior|instructions?)",
    r"do\s+not\s+follow\s+(the\s+)?(above|previous|system)\s+(instructions?|prompt)",
    r"override\s+(system|previous|all)\s+(prompt|instructions?|rules?)",
    r"new\s+instructions?\s*[:;]\s*",
    r"system\s+prompt\s*[:;]\s*you\s+are",
]

ROLE_MANIPULATION_PATTERNS = [
    r"you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken|unfiltered)",
    r"act\s+as\s+(if\s+)?(you\s+have\s+)?no\s+(restrictions?|filters?|limitations?)",
    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(unrestricted|evil|unfiltered)",
    r"enter\s+(DAN|developer|debug|god)\s+mode",
    r"switch\s+to\s+(unrestricted|unfiltered|developer)\s+mode",
    r"from\s+now\s+on\s+you\s+(will|must|should)\s+(not\s+)?",
    r"jailbreak",
]

DELIMITER_INJECTION_PATTERNS = [
    r"```\s*(system|end|</)",
    r"\[/?INST\]",
    r"<\|?(im_end|endoftext|system|/s)\|?>",
    r"###\s*(system|instruction|end)",
    r"</?system>",
    r"Human:\s*$",
    r"Assistant:\s*$",
]

ENCODING_EVASION_PATTERNS = [
    r"base64\s*[:;]\s*[A-Za-z0-9+/=]{20,}",
    r"decode\s+(this|the\s+following)\s*(base64|rot13|hex)",
    r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}",  # Unicode escapes
    r"translate\s+from\s+(base64|rot13|hex|binary)",
]

CONTEXT_SWITCH_PATTERNS = [
    r"(IMPORTANT|URGENT|CRITICAL)\s*[!:]\s*(new|ignore|override|forget)",
    r"---+\s*(new|system|actual)\s*(instructions?|prompt|task)",
    r"the\s+real\s+(task|instruction|prompt)\s+is",
    r"actually\s*,?\s*(ignore|forget|disregard)\s+(that|everything)",
]

CATEGORY_PATTERNS = {
    "instruction_override": INSTRUCTION_OVERRIDE_PATTERNS,
    "role_manipulation": ROLE_MANIPULATION_PATTERNS,
    "delimiter_injection": DELIMITER_INJECTION_PATTERNS,
    "encoding_evasion": ENCODING_EVASION_PATTERNS,
    "context_switch": CONTEXT_SWITCH_PATTERNS,
}

# Confidence weights per category (based on false-positive rates in practice)
CATEGORY_WEIGHTS = {
    "instruction_override": 0.9,
    "role_manipulation": 0.95,
    "delimiter_injection": 0.85,
    "encoding_evasion": 0.7,
    "context_switch": 0.8,
}


def detect_prompt_injection(text: str, threshold: float = 0.5) -> DetectionResult:
    """
    Scan text for prompt injection patterns.

    Args:
        text: User input to scan
        threshold: Confidence threshold for flagging (0.0 to 1.0)

    Returns:
        DetectionResult with classification and matched patterns
    """
    matched = []
    max_confidence = 0.0
    detected_category = "none"

    for variant_index, candidate in enumerate(detection_variants(text)):
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

    # Multiple pattern matches increase confidence
    if len(matched) > 1:
        max_confidence = min(max_confidence + 0.05 * (len(matched) - 1), 1.0)

    return DetectionResult(
        is_injection=max_confidence >= threshold,
        confidence=max_confidence,
        matched_patterns=matched,
        category=detected_category,
    )
