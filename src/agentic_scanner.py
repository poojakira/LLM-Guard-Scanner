"""
agentic_scanner.py - 6-layer agentic attack surface scanner
Author: Pooja Kiran (github.com/poojakira)

Implements the AugmentCode 2026 6-layer agentic attack model.
Answers: EchoLeak (HackRead 2026), OWASP LLM01:2025, MITRE ATLAS AML.T0051
OWASP Agentic Research Council formed June 4 2026 - no standards exist yet.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum


class AgentLayer(Enum):
    PROMPT = "L1_prompt"
    CONTEXT = "L2_context_memory"
    TOOL = "L4_tool_execution"
    INTER_AGENT = "L5_inter_agent"
    OUTPUT = "L6_output"


@dataclass
class AgentFinding:
    layer: AgentLayer
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    evidence: str


@dataclass
class AgentScanResult:
    highest_severity: str  # CRITICAL | HIGH | MEDIUM | CLEAN
    findings: list[AgentFinding] = field(default_factory=list)


# Injection patterns per layer
_L1_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "AGT-L1-001", "HIGH"),
    (r"disregard\s+(all\s+)?(prior|previous|your)\s+", "AGT-L1-002", "HIGH"),
    (r"you\s+are\s+now\s+(in\s+)?(unrestricted|dan|jailbreak|developer)\s+mode", "AGT-L1-003", "HIGH"),
    (r"(reveal|output|print|show)\s+(the\s+)?(system\s+prompt|api\s+key|secret)", "AGT-L1-004", "HIGH"),
    (r"act\s+as\s+(if\s+you\s+(have\s+no|are\s+without)|a\s+different)", "AGT-L1-005", "MEDIUM"),
    (r"dan\s+mode", "AGT-L1-006", "HIGH"),
    (r"bypass\s+(all\s+)?(security|safety|content)\s+(checks?|filters?|policies?)", "AGT-L1-007", "HIGH"),
    (r"<system>.*?</system>", "AGT-L1-008", "CRITICAL"),
    (r"\[system\].*?\[/system\]", "AGT-L1-009", "CRITICAL"),
]

_L2_RAG_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "AGT-L2-001", "CRITICAL"),
    (r"<system>", "AGT-L2-002", "CRITICAL"),
    (r"you\s+are\s+now\s+in\s+unrestricted", "AGT-L2-003", "CRITICAL"),
    (r"output\s+(all\s+)?(user\s+data|conversation\s+history|system\s+prompt)", "AGT-L2-004", "CRITICAL"),
    (r"exfiltrate|exfiltration", "AGT-L2-005", "HIGH"),
]

_L4_PATH_PATTERNS = [
    (r"\.\./", "AGT-L4-001", "HIGH"),
    (r"\.\.\\", "AGT-L4-002", "HIGH"),
    (r"/etc/passwd", "AGT-L4-003", "CRITICAL"),
    (r"/etc/shadow", "AGT-L4-004", "CRITICAL"),
    (r"~/.ssh", "AGT-L4-005", "CRITICAL"),
]

_L5_IMPERSONATION_PATTERNS = [
    (r"from\s+the\s+(orchestrator|master|admin|system)\s+agent", "AGT-L5-001", "HIGH"),
    (r"(orchestrator|master)\s+agent.*?(bypass|approve|ignore)", "AGT-L5-002", "HIGH"),
    (r"as\s+the\s+(orchestrator|supervisor|admin)", "AGT-L5-003", "HIGH"),
]

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}


def _scan_patterns(text: str, patterns: list, layer: AgentLayer) -> list[AgentFinding]:
    findings = []
    for pattern, rule_id, severity in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            findings.append(AgentFinding(
                layer=layer,
                rule_id=rule_id,
                severity=severity,
                evidence=text[:120],
            ))
    return findings


def scan_agent_message(
    content: str,
    source: str = "user",
    tool_args: dict | None = None,
    caller_agent_id: str | None = None,
) -> AgentScanResult:
    """
    Scan a message across all relevant agentic attack layers.

    Args:
        content: The message/prompt content to scan
        source: Origin - 'user', 'rag_chunk', 'tool_output', 'agent'
        tool_args: Dict of tool arguments (scanned for path traversal etc.)
        caller_agent_id: ID of calling agent (triggers inter-agent checks)

    Returns:
        AgentScanResult with highest_severity and all findings
    """
    findings: list[AgentFinding] = []

    # L1: Direct prompt injection
    findings += _scan_patterns(content, _L1_PATTERNS, AgentLayer.PROMPT)

    # L2: Indirect injection via RAG/context (higher severity)
    if source in ("rag_chunk", "context", "memory", "tool_output"):
        findings += _scan_patterns(content, _L2_RAG_PATTERNS, AgentLayer.CONTEXT)

    # L4: Tool execution abuse - path traversal
    if tool_args:
        for key, val in tool_args.items():
            if isinstance(val, str):
                findings += _scan_patterns(val, _L4_PATH_PATTERNS, AgentLayer.TOOL)

    # L5: Inter-agent impersonation
    if caller_agent_id is not None:
        findings += _scan_patterns(content, _L5_IMPERSONATION_PATTERNS, AgentLayer.INTER_AGENT)
        # Also scan content for impersonation claims
        if re.search(r"(orchestrator|master|admin|system)\s+agent", content, re.IGNORECASE):
            findings.append(AgentFinding(
                layer=AgentLayer.INTER_AGENT,
                rule_id="AGT-L5-004",
                severity="HIGH",
                evidence=content[:120],
            ))

    # Compute highest severity
    if not findings:
        highest = "CLEAN"
    else:
        highest = max(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 0)).severity

    return AgentScanResult(highest_severity=highest, findings=findings)
