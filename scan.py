"""CLI entry point for LLM Guard Scanner."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.detectors import detect_prompt_injection, scan_retrieved_document
from src.guardrails import scan_output

# Only text-like files make sense here — binary formats not supported
SUPPORTED_TEXT_EXTENSIONS = {".txt", ".md", ".json", ".yaml", ".yml", ".log"}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llm-guard",
        description="LLM Guard Scanner — detect prompt injection, PII leakage, RAG poisoning",
    )
    parser.add_argument("--input", type=str, help="Text to scan for prompt injection")
    parser.add_argument("--file", type=str, help="File with one prompt per line")
    parser.add_argument("--output-scan", type=str, help="Scan LLM output for data leakage")
    parser.add_argument("--rag-scan", type=str, help="Scan a document for RAG poisoning")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.input:
        result = detect_prompt_injection(args.input, threshold=args.threshold)
        if args.as_json:
            print(json.dumps({
                "is_injection": result.is_injection,
                "confidence": result.confidence,
                "category": result.category,
                "patterns": result.matched_patterns,
            }, indent=2))
        else:
            status = "BLOCKED" if result.is_injection else "PASS"
            print(f"[{status}] confidence={result.confidence:.0%} category={result.category}")
            for p in result.matched_patterns:
                print(f"  - {p}")

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
            result = detect_prompt_injection(line, threshold=args.threshold)
            if result.is_injection:
                blocked += 1
                print(f"  [BLOCKED] {line[:80]} ({result.category})")
        print(f"\nResults: {blocked}/{total} blocked ({100 * blocked / max(total, 1):.1f}%)")

    elif args.output_scan:
        result = scan_output(args.output_scan)
        if args.as_json:
            print(json.dumps({
                "is_safe": result.is_safe,
                "violations": result.violations,
                "redacted_text": result.redacted_text,
            }, indent=2))
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
        if args.as_json:
            print(json.dumps({
                "is_poisoned": result.is_poisoned,
                "risk_score": result.risk_score,
                "findings": result.findings,
            }, indent=2))
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
