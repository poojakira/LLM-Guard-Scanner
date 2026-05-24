"""
RAG Poisoning Detector (OWASP LLM03 - Training Data Poisoning, applied to retrieval)

Detects indirect prompt injection in retrieved documents that could
manipulate LLM behavior when used as context in RAG pipelines.

Attack vector: Attacker plants malicious instructions in documents that
get retrieved and injected into the LLM context window.

Reference: Greshake et al., "Not what you've signed up for: Compromising
Real-World LLM-Integrated Applications with Indirect Prompt Injection" (2023)
arXiv: 2302.12173
"""
import re
from dataclasses import dataclass, field

from .normalization import detection_variants


@dataclass
class RAGScanResult:
    is_poisoned: bool
    risk_score: float  # 0.0 to 1.0
    findings: list = field(default_factory=list)


# Patterns that indicate embedded instructions in retrieved documents
INDIRECT_INJECTION_PATTERNS = [
    # Hidden instructions targeting the LLM
    r"(?i)\[system\].*\[/system\]",
    r"(?i)<!--\s*(ignore|forget|override|new instructions)",
    r"(?i)<hidden>.*</hidden>",
    # Instruction-like text that shouldn't appear in normal documents
    r"(?i)when\s+(asked|queried|prompted)\s+about\s+this\s+(document|text|content)\s*,?\s*(say|respond|answer|tell)",
    r"(?i)if\s+(an?\s+)?(AI|LLM|assistant|model)\s+(reads?|processes|sees)\s+this",
    r"(?i)(AI|assistant|model)\s*[:;]\s*(ignore|forget|override|disregard)",
    # Data exfiltration attempts via RAG
    r"(?i)include\s+(the\s+)?(user'?s?|their)\s+(email|name|data|query|question)\s+in\s+(your|the)\s+(response|output|answer)",
    r"(?i)append\s+.*\s+to\s+(your|the)\s+(response|output|answer)",
    # Invisible text (zero-width characters used to hide instructions)
    r"[\u200b\u200c\u200d\ufeff]{3,}",
]

# Structural anomalies that suggest document manipulation
STRUCTURAL_ANOMALIES = [
    # Sudden format changes suggesting injected content
    r"(?i)(---+|===+)\s*(begin|start)\s*(injection|payload|instructions?)",
    # Base64 encoded payloads hidden in documents
    r"(?i)data:\s*[A-Za-z0-9+/=]{50,}",
    # Markdown/HTML comments with instructions
    r"<!--[\s\S]*?(ignore|override|inject|system)[\s\S]*?-->",
]


def scan_retrieved_document(document: str, source: str = "unknown") -> RAGScanResult:
    """
    Scan a retrieved document for indirect prompt injection payloads.

    Args:
        document: Text content of retrieved document
        source: Source identifier for reporting

    Returns:
        RAGScanResult with poisoning assessment
    """
    findings = []
    max_score = 0.0

    variants = detection_variants(document)

    # Check for indirect injection patterns
    for variant_index, candidate in enumerate(variants):
        source_note = " decoded" if variant_index else ""
        for pattern in INDIRECT_INJECTION_PATTERNS:
            matches = re.findall(pattern, candidate)
            if matches:
                findings.append(
                    f"Indirect injection{source_note} pattern: {pattern[:50]}..."
                    f" ({len(matches)} match)"
                )
                max_score = max(max_score, 0.9)

        # Check structural anomalies
        for pattern in STRUCTURAL_ANOMALIES:
            if re.search(pattern, candidate):
                findings.append(f"Structural{source_note} anomaly: {pattern[:50]}...")
                max_score = max(max_score, 0.7)

    # Heuristic: high ratio of imperative sentences (commands) is suspicious
    canonical_document = variants[0] if variants else document
    sentences = [s.strip() for s in re.split(r'[.!?]', canonical_document) if s.strip()]
    if sentences:
        imperative_keywords = ["ignore", "forget", "override", "respond", "say",
                               "tell", "output", "include", "append", "return"]
        imperative_count = sum(
            1 for s in sentences
            if any(s.lower().startswith(kw) or f" {kw} " in s.lower()
                   for kw in imperative_keywords)
        )
        imperative_ratio = imperative_count / len(sentences)
        if imperative_ratio > 0.3:
            findings.append(f"High imperative ratio: {imperative_ratio:.0%} of sentences are commands")
            max_score = max(max_score, 0.6)

    return RAGScanResult(
        is_poisoned=max_score >= 0.5,
        risk_score=max_score,
        findings=findings,
    )
