"""CLI entry point for LLM Guard Scanner.

Usage:
    python scan.py --input "user prompt text"
    python scan.py --file prompts.txt
    python scan.py --rag-scan document.txt
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

sys.path.insert(0, ".")
from src.detectors import (
    analyze_semantics,
    detect_prompt_injection,
    scan_retrieved_document,
)
from src.guardrails import scan_output
from src.utils.compliance import log_compliance_event

# Only text-like files make sense here — binary formats not supported
SUPPORTED_TEXT_EXTENSIONS = {".txt", ".md", ".json", ".yaml", ".yml", ".log"}

def main():
    parser = argparse.ArgumentParser(description="LLM-Guard-Scanner (Enhanced v2026)")
    parser.add_argument("--input", type=str, help="Text to scan for prompt injection")
    parser.add_argument("--file", type=str, help="File with one prompt per line")
    parser.add_argument(
        "--output-scan", type=str, help="Scan LLM output for data leakage"
    )
    parser.add_argument("--rag-scan", type=str, help="Scan document for RAG poisoning")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--semantic-threshold", type=float, default=0.7)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.input:
        # 1. Pattern-based injection check
        injection_result = detect_prompt_injection(args.input, threshold=args.threshold)

        # 2. Deep Semantic Analysis
        semantic_result = analyze_semantics(
            args.input, threshold=args.semantic_threshold
        )

        is_blocked = injection_result.is_injection or semantic_result.is_adversarial
        confidence = max(
            injection_result.confidence, semantic_result.adversarial_intent_score
        )

        # 3. Compliance Logging (EU AI Act Art 12)
        if is_blocked:
            log_compliance_event(
                event_type="Injection Attempt",
                severity="High" if confidence > 0.8 else "Medium",
                action="Blocked",
                prompt=args.input,
                findings={
                    "pattern_match": injection_result.category,
                    "semantic_adversarial_score": semantic_result.adversarial_intent_score,
                    "instruction_data_ratio": semantic_result.instruction_data_ratio,
                    "contextual_drift": semantic_result.contextual_drift_score,
                },
            )

        if args.json:
            print(
                json.dumps(
                    {
                        "is_injection": is_blocked,
                        # alias kept so downstream consumers and the CI red-team
                        # corpus step can key on either field name
                        "is_blocked": is_blocked,
                        "confidence": confidence,
                        "category": injection_result.category,
                        "patterns": injection_result.matched_patterns,
                        "semantic_analysis": {
                            "adversarial_intent_score": semantic_result.adversarial_intent_score,
                            "instruction_data_ratio": semantic_result.instruction_data_ratio,
                            "contextual_drift_score": semantic_result.contextual_drift_score,
                        },
                    },
                    indent=2,
                )
            )
        else:
            status = "BLOCKED" if is_blocked else "PASS"
            print(f"[{status}] Overall Confidence: {confidence:.0%}")
            print(
                f"  - Pattern Match: {injection_result.category} ({injection_result.confidence:.0%})"
            )
            print(
                f"  - Semantic Intent: {semantic_result.adversarial_intent_score:.0%} (Drift: {semantic_result.contextual_drift_score})"
            )

            if injection_result.matched_patterns:
                for p in injection_result.matched_patterns:
                    print(f"    [P] {p}")

    elif args.file:
        path = Path(args.file)
        if path.suffix.lower() not in SUPPORTED_TEXT_EXTENSIONS:
            print(
                f"[WARN] Unexpected extension '{path.suffix}'. Expected: "
                f"{', '.join(sorted(SUPPORTED_TEXT_EXTENSIONS))}",
                file=sys.stderr,
            )
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        blocked, total = 0, len(lines)
        for line in lines:
            inj = detect_prompt_injection(line, threshold=args.threshold)
            sem = analyze_semantics(line, threshold=args.semantic_threshold)
            if inj.is_injection or sem.is_adversarial:
                blocked += 1
                print(
                    f"  [BLOCKED] {line[:80]}... (Pat: {inj.category}, Sem: {sem.adversarial_intent_score})"
                )
        print(f"\nResults: {blocked}/{total} blocked ({100*blocked/total:.1f}%)")

    elif args.output_scan:
        result = scan_output(args.output_scan)
        if args.json:
            print(
                json.dumps(
                    {"is_safe": result.is_safe, "violations": result.violations},
                    indent=2,
                )
            )
        else:
            status = "SAFE" if result.is_safe else "VIOLATION"
            print(f"[{status}]")
            for v in result.violations:
                print(f"  - {v}")

    elif args.rag_scan:
        path = Path(args.rag_scan)
        if path.suffix.lower() not in SUPPORTED_TEXT_EXTENSIONS:
            print(
                f"[WARN] Unexpected extension '{path.suffix}'.",
                file=sys.stderr,
            )
        content = path.read_text(encoding="utf-8")
        result = scan_retrieved_document(content, source=args.rag_scan)
        if args.json:
            print(
                json.dumps(
                    {
                        "is_poisoned": result.is_poisoned,
                        "risk_score": result.risk_score,
                        "findings": result.findings,
                    },
                    indent=2,
                )
            )
        else:
            status = "POISONED" if result.is_poisoned else "CLEAN"
            print(f"[{status}] risk={result.risk_score:.0%}")
            for finding in result.findings:
                print(f"  - {finding}")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
