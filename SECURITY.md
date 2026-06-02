# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Current Release |

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

## Security Implementation

### 1. Multi-Layered Defense
We use a defense-in-depth approach combining regex, heuristics, and optional ML classifiers to catch both known and novel injection patterns.

### 2. Output Sanitization
All LLM outputs are scanned for PII and secrets before being returned to the user, preventing unintentional data leakage.

### 3. RAG Integrity
Documents ingested into the RAG pipeline are audited for indirect prompt injection to prevent "Man-in-the-Middle" attacks on the knowledge base.

## Known Limitations

- **Adversarial Evasion**: Highly sophisticated, low-perplexity adversarial attacks may bypass pattern-based and heuristic detectors.
- **Contextual Nuance**: LLM security is inherently probabilistic. This tool is a guardrail, not a perfect firewall.
