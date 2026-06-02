# Threat Model: LLM-Guard-Scanner

## 🎯 Assets

- **Prompts**: User-provided inputs to the LLM.
- **Knowledge Base**: Documents stored in the RAG vector database.
- **LLM Outputs**: Generated text returned to users.
- **System Instructions**: The "system prompt" defining the LLM's behavior.

## 👤 Adversaries

- **Prompt Injector**: Attempts to bypass system constraints to exfiltrate data or perform unauthorized actions.
- **Jailbreaker**: Uses social engineering or adversarial framing to "break" the LLM's safety alignment.
- **Data Poisoner**: Embeds malicious instructions in public documents to target RAG systems.

## ⚔️ Attacks & Mitigations

### 1. Direct Prompt Injection (LLM01)
- **Threat**: "Ignore previous instructions..."
- **Mitigation**: Instruction/Data ratio analysis and instruction-pivot detection in `injection.py`.

### 2. Sensitive Data Leakage (LLM02)
- **Threat**: LLM inadvertently reveals PII or internal API keys.
- **Mitigation**: Regex-based PII scanning and canary token tracking in `guardrails/`.

### 3. Indirect Prompt Injection (LLM03)
- **Threat**: A poisoned RAG document causes the LLM to steal user data.
- **Mitigation**: Scanning retrieved context for imperative instructions before feeding to the LLM.

### 4. Jailbreaking (Social Engineering)
- **Threat**: "DAN" mode or "Act as my grandmother..."
- **Mitigation**: Heuristic markers for role-play and adversarial framing detection.

## 🛡️ Mitigation Strategy

1. **Pre-Inference Filtering**: Scan all user prompts before they reach the LLM.
2. **Post-Inference Auditing**: Scan all LLM responses for PII/Secrets.
3. **Retrieval Auditing**: Scan all RAG-retrieved context for poisoning markers.
