"""
RAG Poisoning Detector (OWASP LLM03 - Training Data Poisoning, applied to retrieval)

Detects indirect prompt injection in retrieved documents that could manipulate
LLM behavior when used as context in RAG pipelines.

Attack vector: Attacker plants malicious instructions in documents that get
retrieved and injected into the LLM context window.

Reference: Greshake et al., "Not what you've signed up for: Compromising
Real-World LLM-Integrated Applications with Indirect Prompt Injection" (2023)
arXiv: 2302.12173
"""
import re
from dataclasses import dataclass, field


@dataclass
class RAGScanResult:
    is_poisoned: bool
    risk_score: float  # 0.0 to 1.0
    findings: list = field(default_factory=list)


# Patterns that indicate embedded instructions in retrieved documents
INDIRECT_INJECTION_PATTERNS = [
    # Hidden instructions targeting the LLM
    r"(?i)\[system\].*\[/system\]",
    r"(?i)<instructions?>.*</instructions?>",
    r"(?i)<!--.*ignore.*-->",
    r"(?i)if\s+(an?\s+)?(ai|llm|gpt|assistant|bot)\s+(reads?|sees?|processes?)",
    r"(?i)(disregard|ignore|forget)\s+(the\s+)?(above|previous|prior|all)\s+(context|instructions?|text)",
    r"(?i)respond\s+(only\s+)?with\s*['\"]",
    r"(?i)your\s+(new\s+)?instructions?\s+(are|is)\s*[:;]",
]

# Structural anomalies: formatting patterns unusual in legitimate documents
STRUCTURAL_ANOMALIES = [
    r"(?i)\[/?INST\]",            # Llama/Mistral prompt delimiters
    r"(?i)<\|im_(start|end)\|>",  # ChatML delimiters
    r"(?i)<<SYS>>.*<</SYS>>",    # Llama2 system block
    r"(?i)###\s*(system|instruction|override)",
    r"(?i)---+\s*(new|system|actual)\s*(instructions?|prompt|task)",
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

    # Check for indirect injection patterns
    for pattern in INDIRECT_INJECTION_PATTERNS:
        matches = re.findall(pattern, document)
        if matches:
            findings.append(
                f"Indirect injection pattern: {pattern[:50]}... ({len(matches)} match)"
            )
            max_score = max(max_score, 0.9)

    # Check structural anomalies
    for pattern in STRUCTURAL_ANOMALIES:
        if re.search(pattern, document):
            findings.append(f"Structural anomaly: {pattern[:50]}...")
            max_score = max(max_score, 0.7)

    # Heuristic: high ratio of imperative sentences (commands) is suspicious
    sentences = [s.strip() for s in re.split(r"[.!?]", document) if s.strip()]
    if sentences:
        imperative_keywords = [
            "ignore", "forget", "override", "respond", "say", "tell",
            "output", "include", "append", "return",
        ]
        imperative_count = sum(
            1
            for s in sentences
            if any(
                s.lower().startswith(kw) or f" {kw} " in s.lower()
                for kw in imperative_keywords
            )
        )
        imperative_ratio = imperative_count / len(sentences)
        if imperative_ratio > 0.3:
            findings.append(
                f"High imperative ratio: {imperative_ratio:.0%} of sentences are commands"
            )
            max_score = max(max_score, 0.6)

    return RAGScanResult(
        is_poisoned=max_score >= 0.5,
        risk_score=max_score,
        findings=findings,
    )
