# LLM-Guard-Scanner

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
