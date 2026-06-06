# Evaluation Metrics and Benchmark Corpus

## Evaluation Metrics
- **Precision**: Ratio of correctly identified threats to total identified threats.
- **Recall**: Ratio of correctly identified threats to total actual threats.
- **F1-Score**: Harmonic mean of Precision and Recall.
- **False Positive Rate (FPR)**: Rate at which benign inputs are flagged as threats.

## Benchmark Corpus
The system is evaluated against the following corpora:
1. **OWASP Top 10 for LLM**: Standardized test cases for prompt injection and data leakage.
2. **Red Team Corpus**: Located in `data/payloads/red_team_corpus.txt`.
3. **Synthetic Poisoning Dataset**: Generated for RAG poisoning evaluation.
