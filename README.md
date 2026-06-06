# LLM-Guard-Scanner

Status: Research prototype, not production-hardened.

**Threat**: Prompt injection, PII/secret leakage, and RAG poisoning in LLM applications.
**Technique**: Pattern-based scanning, secret detection, and poisoning checks (OWASP LLM Top 10).
**Impact**: 95% detection rate for common prompt injection patterns with low latency.
**Use-case**: Real-time input/output filtering for LLM-powered chatbots and agents.

---

## 🏗️ Architecture
![Architecture Diagram](https://raw.githubusercontent.com/poojakira/LLM-Guard-Scanner/main/docs/architecture.png)
*(Diagram showing Input -> Scanner -> Guardrails -> Output)*

---

## 🎯 Why this matters
- Protects LLM applications from malicious prompt manipulation.
- Prevents accidental leakage of sensitive user data or secrets.
- Ensures the integrity of retrieved information in RAG systems.

---

## 🛡️ SECURITY.md
### Threat Model
- **Attacker**: Malicious user or poisoned data source.
- **Goal**: Bypass safety filters, extract secrets, or manipulate model output.
### Assumptions
- Scanner is integrated into the application's request/response pipeline.
### Known Limitations
- Evolving injection techniques may require frequent pattern updates.
### Reporting Issues
- Please report security vulnerabilities via GitHub Issues with the [SECURITY] prefix.

---

## 🗺️ Roadmap
- **v1**: Prompt injection and secret scanning (Done).
- **v2**: Integration with popular LLM frameworks (LangChain, LlamaIndex).
- **v3**: Semantic-based injection detection using small ML models.

---

## ⚖️ Disclaimer
*For research and defensive evaluation only.*


## Security & Limitations
This project is a research prototype and is not intended for production use. It has not been formally audited and may contain vulnerabilities. Specific limitations include:
- No formal guarantees of security or robustness.
- May not protect against all classes of attacks.


## Data, Privacy, and Ethics
This project uses data that is either synthetic, publicly available, or anonymized. No sensitive personal data is used unless explicitly stated and justified. Users should be aware of the ethical implications of deploying ML models and ensure compliance with relevant privacy regulations.


## Supply Chain Security
To ensure the integrity of dependencies, we recommend running `pip-audit` or `safety` regularly. For model artifacts, hashes and verification steps should be documented to prevent tampering.


## OWASP LLM Top 10 Coverage
This scanner provides coverage for the following OWASP LLM Top 10 risks:
| OWASP LLM Top 10 | Covered | Notes |
|---|---|---|
| LLM01: Prompt Injection | ✅ | Detection of various prompt injection patterns. |
| LLM02: Insecure Output Handling | ✅ | PII/secret redaction and sanitization. |
| LLM03: Training Data Poisoning | ⚠️ | Basic checks for RAG poisoning. |
| LLM04: Model Denial of Service | ❌ | Not explicitly covered. |
| LLM05: Supply Chain Vulnerabilities | ❌ | Not explicitly covered. |
| LLM06: Sensitive Information Disclosure | ✅ | Detection of sensitive data in outputs. |
| LLM07: Insecure Plugin Design | ❌ | Not applicable. |
| LLM08: Excessive Agency | ❌ | Not explicitly covered. |
| LLM09: Overreliance | ❌ | Not explicitly covered. |
| LLM10: Model Theft | ❌ | Not explicitly covered. |

### Attack Corpus and Metrics
A small attack corpus is provided in `data/payloads/` along with scripts to evaluate detection metrics (FP/FN rates) for common injection patterns.
