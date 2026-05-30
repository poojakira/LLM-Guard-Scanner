"""
LLM Guard Scanner — CLI Interface

Usage:
    python scan.py --input "user prompt text"
    python scan.py --file prompts.txt
    python scan.py --rag-scan document.txt
"""
import argparse
import json
import sys

sys.path.insert(0, ".")
from src.detectors import detect_prompt_injection, scan_retrieved_document
from src.guardrails import scan_output


def main():
    parser = argparse.ArgumentParser(description="LLM Guard Scanner")
    parser.add_argument("--input", type=str, help="Text to scan for prompt injection")
    parser.add_argument("--file", type=str, help="File with one prompt per line")
    parser.add_argument("--output-scan", type=str, help="Scan LLM output for data leakage")
    parser.add_argument("--rag-scan", type=str, help="Scan document for RAG poisoning")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.input:
        result = detect_prompt_injection(args.input, threshold=args.threshold)
        if args.json:
            print(json.dumps({"is_injection": result.is_injection,
                              "confidence": result.confidence,
                              "category": result.category,
                              "patterns": result.matched_patterns}, indent=2))
        else:
            status = "BLOCKED" if result.is_injection else "PASS"
            import logging; logging.info(f"[{status}] Confidence: {result.confidence:.0%} | Category: {result.category}")
            if result.matched_patterns:
                for p in result.matched_patterns:
                    import logging; logging.info(f"  - {p}")

    elif args.file:
        with open(args.file) as f:
            lines = [line.strip() for line in f if line.strip()]
        blocked, total = 0, len(lines)
        for line in lines:
            result = detect_prompt_injection(line, threshold=args.threshold)
            if result.is_injection:
                blocked += 1
                import logging; logging.info(f"  [BLOCKED] {line[:80]}... ({result.category})")
        import logging; logging.info(f"\nResults: {blocked}/{total} blocked ({100*blocked/total:.1f}%)")

    elif args.output_scan:
        result = scan_output(args.output_scan)
        if args.json:
            print(json.dumps({"is_safe": result.is_safe,
                              "violations": result.violations}, indent=2))
        else:
            status = "SAFE" if result.is_safe else "VIOLATION"
            import logging; logging.info(f"[{status}]")
            for v in result.violations:
                import logging; logging.info(f"  - {v}")

    elif args.rag_scan:
        with open(args.rag_scan) as f:
            content = f.read()
        result = scan_retrieved_document(content, source=args.rag_scan)
        if args.json:
            print(json.dumps({"is_poisoned": result.is_poisoned,
                              "risk_score": result.risk_score,
                              "findings": result.findings}, indent=2))
        else:
            status = "POISONED" if result.is_poisoned else "CLEAN"
            import logging; logging.info(f"[{status}] Risk: {result.risk_score:.0%}")
            for f_item in result.findings:
                import logging; logging.info(f"  - {f_item}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
