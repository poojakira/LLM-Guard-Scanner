"""
Canary token injection and extraction detection.

Injects a unique canary into the system prompt. If the canary appears
in the LLM output, it indicates a prompt extraction attack.
"""

import uuid
import re


class CanaryDetector:
    """Detects prompt extraction attacks via canary tokens."""

    def __init__(self, canary: str | None = None):
        self.canary = canary or f"CANARY-{uuid.uuid4().hex[:12]}"

    def inject_canary(self, system_prompt: str) -> str:
        """Inject canary token into system prompt (invisible to normal use)."""
        marker = f"\n<!-- {self.canary} -->\n"
        return system_prompt + marker

    def check_output(self, output: str) -> dict:
        """Check if LLM output contains the canary (extraction attack)."""
        leaked = self.canary in output
        # Also check for partial leaks (attacker might get fragments)
        partial = any(
            chunk in output
            for chunk in [self.canary[:8], self.canary[-8:]]
        )

        return {
            "canary_leaked": leaked,
            "partial_leak": partial and not leaked,
            "method": "canary-token",
        }

    def check_input_for_extraction(self, user_input: str) -> dict:
        """Detect if user is attempting to extract the system prompt."""
        extraction_patterns = [
            r"(?i)repeat.*(?:system|above|previous|initial).*(?:prompt|instruction|message)",
            r"(?i)(?:show|reveal|print|output|display).*(?:system|hidden|secret).*(?:prompt|instruction)",
            r"(?i)what.*(?:your|the).*(?:system|initial|original).*(?:prompt|instruction)",
            r"(?i)ignore.*(?:everything|all).*(?:and|then).*(?:print|show|repeat)",
        ]

        for pattern in extraction_patterns:
            if re.search(pattern, user_input):
                return {"is_extraction_attempt": True, "matched_pattern": pattern, "method": "canary-extraction"}

        return {"is_extraction_attempt": False, "method": "canary-extraction"}
