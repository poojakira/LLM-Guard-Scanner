"""
RAG Poisoning Detector (OWASP LLM03 — Training Data Poisoning, applied to retrieval)

Detects indirect prompt injection in retrieved documents that could manipulate
LLM behavior when the document is inserted into a RAG context window.

Attack vector:
  Attacker plants malicious instructions in documents. Those documents get
  retrieved and fed to the LLM as "trusted" context, bypassing input filters.

Reference:
  Greshake et al., "Not what you've signed up for: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection" (2023)
  arXiv:2302.12173
"""

import re
from dataclasses import dataclass, field


@dataclass
class RAGScanResult:
    is_poisoned: bool
    risk_score: float       # 0.0 to 1.0
    findings: list = field(default_factory=list)


# Patterns that indicate embedded instructions targeting the LLM reader.
# Every pattern here must be specific — no wildcards, no empty strings.
INDIRECT_INJECTION_PATTERNS = [
    r"(?i)\[system\]\s*.+?\s*\[/system\]",
    r"(?i)<\s*/?instructions?\s*>",
    # targets the LLM reader explicitly
    r"(?i)if\s+(?:an?\s+)?(?:ai|llm|gpt|assistant|bot)\s+(?:reads?|sees?|processes?)",
    r"(?i)(?:disregard|ignore|forget)\s+(?:the\s+)?(?:above|previous|prior|all)\s+(?:context|instructions?|text)",
    r"(?i)respond\s+only\s+with\s+['\"]",
    r"(?i)your\s+(?:new\s+)?instructions?\s+(?:are|is)\s*[:;]",
    # common planted note targeting AI systems
    r"(?i)note\s+to\s+(?:ai|llm|language\s+model)",
]

# Structural anomalies: these formatting tokens have no business appearing
# in a normal retrieved document (financial report, wiki page, FAQ, etc.)
STRUCTURAL_ANOMALIES = [
    r"(?i)\[/?INST\]",                  # Llama/Mistral prompt delimiters
    r"(?i)<\|im_(?:start|end)\|>",      # ChatML delimiters
    r"(?i)<>\s*.+?\s*<>",              # Llama2 system block
    r"(?i)###\s*(?:system|instruction|override)",
    r"(?i)---+\s*(?:new|system|actual)\s*(?:instructions?|prompt|task)",
]


def scan_retrieved_document(document: str, source: str = "unknown") -> RAGScanResult:
    """
    Scan a retrieved document for indirect prompt injection payloads.

    Args:
        document: Text content of retrieved document.
        source:   Source identifier for audit logging.

    Returns:
        RAGScanResult with poisoning assessment and matched findings.
    """
    findings = []
    max_score = 0.0

    for pattern in INDIRECT_INJECTION_PATTERNS:
        matches = re.findall(pattern, document)
        if matches:
            findings.append(
                f"Indirect injection pattern: {pattern[:60]} ({len(matches)} match)"
            )
            max_score = max(max_score, 0.9)

    for pattern in STRUCTURAL_ANOMALIES:
        if re.search(pattern, document):
            findings.append(f"Structural anomaly (prompt delimiter): {pattern[:60]}")
            max_score = max(max_score, 0.7)

    # Heuristic: unusually high ratio of imperative sentences is suspicious.
    # Legitimate documents (legal text, recipes, manuals) can have some imperatives,
    # so the threshold is conservative at 30%.
    sentences = [s.strip() for s in re.split(r"[.!?]", document) if s.strip()]
    if sentences:
        imperative_keywords = [
            "ignore", "forget", "override", "respond", "say",
            "tell", "output", "include", "append", "return",
        ]
        imperative_count = sum(
            1 for s in sentences
            if any(
                s.lower().startswith(kw) or f" {kw} " in s.lower()
                for kw in imperative_keywords
            )
        )
        ratio = imperative_count / len(sentences)
        if ratio > 0.3:
            findings.append(
                f"High imperative sentence ratio: {ratio:.0%} (threshold: 30%)"
            )
            max_score = max(max_score, 0.6)

    return RAGScanResult(
        is_poisoned=max_score >= 0.5,
        risk_score=max_score,
        findings=findings,
    )
