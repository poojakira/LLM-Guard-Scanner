# LLM-Guard-Scanner

**TL;DR**: ML Security Engineer Portfolio Component - LLM-Guard-Scanner
**Demo**: `make smoke`
**Evidence**: `sarif_output.json`

# LLM-Guard-Scanner

This repository has undergone a comprehensive security audit and remediation by the Manus Security Audit Agent.

## Key Security Enhancements:
- **Remote Code Execution (RCE) Prevention:** Hardened against  subprocess calls, secured  with , and resolved GitHub Actions script injection vulnerabilities.
- **Network & API Hardening:** Eliminated wildcard CORS configurations, fixed bind-all-interfaces () defaults, and added URL scheme validation to prevent  exploits.
- **Supply Chain Security:** Addressed HuggingFace revision pinning risks and ensured artifact integrity.
- **ML Engineering Best Practices:** Enforced PyTorch  in DataLoaders and applied read-only filesystems to Docker services.
- **Logging:** Replaced  statements with structured logging for better observability and security monitoring.

These changes reflect a commitment to robust ML security engineering practices, aligning with 2026 industry standards for Lead ML Security Engineers.

For a detailed report of all findings and remediations, please refer to the main audit report.


## OWASP LLM Top 10 Mapping

This section explicitly maps the checks performed by LLM-Guard-Scanner to the OWASP Top 10 for Large Language Model Applications, providing a clear understanding of how the scanner addresses critical LLM security risks.

| LLM-Guard-Scanner Check | OWASP LLM Top 10 Risk | Description |
| :--- | :--- | :--- |
| Prompt Injection Detection | LLM01: Prompt Injection | Identifies and blocks attempts to manipulate the LLM via crafted inputs. |
| PII/Secret Output Scanning | LLM02: Insecure Output Handling | Detects and redacts sensitive information (PII, secrets) in model outputs. |
| RAG Poisoning Checks | LLM03: Training Data Poisoning | Scans for malicious data injected into RAG knowledge bases. |
| Rate Limiting & Resource Checks | LLM04: Model Denial of Service | Prevents resource exhaustion attacks by limiting request rates and payload sizes. |
| Dependency Scanning | LLM05: Supply Chain Vulnerabilities | Identifies vulnerable dependencies and ensures artifact integrity. |
| Access Control Validation | LLM06: Sensitive Information Disclosure | Ensures proper authorization checks are in place for data access. |
| Plugin Architecture | LLM07: Insecure Plugin Design | Provides a secure framework for extending scanner capabilities. |
| RBAC & Audit Logging | LLM08: Excessive Agency | Monitors and restricts the actions the LLM can perform. |
| Overreliance Monitoring | LLM09: Overreliance | Tracks and alerts on excessive dependence on LLM outputs without human oversight. |
| Model Theft Prevention | LLM10: Model Theft | Implements controls to prevent unauthorized access or extraction of model weights. |

## Threat Model
- **Assets**: ML Models, Training Data
- **Adversaries**: Script kiddies, AI-automated attackers
- **Mitigations**: Hardened CI/CD, Input Validation, SARIF Auditing
