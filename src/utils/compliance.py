"""
Compliance Logger for EU AI Act Article 12 (Automatic Logging)

Generates JSON-LD records compatible with regulatory requirements for
High-Risk AI systems and general-purpose AI model reporting.
"""

import datetime
import json
import uuid
from typing import Any, Dict


class ComplianceLogger:
    def __init__(
        self, model_id: str = "llm-guard-scanner-v1", log_path: str = "compliance.log"
    ):
        self.model_id = model_id
        self.log_path = log_path

    def log_event(
        self,
        event_type: str,
        severity: str,
        risk_mitigation: str,
        prompt: str,
        findings: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generates a JSON-LD record for AI security event logging.

        Complies with EU AI Act Article 12 requirements for:
        (a) period of use
        (b) event detection
        (c) risk mitigation application
        """
        record = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                {"eu-ai": "https://data.europa.eu/ns/ai-act#"},
            ],
            "type": "eu-ai:SecurityEvent",
            "id": f"urn:uuid:{uuid.uuid4()}",
            "published": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "actor": {"type": "Application", "id": f"urn:model:{self.model_id}"},
            "object": {
                "type": "Note",
                "content_summary": prompt[:64] + "..." if len(prompt) > 64 else prompt,
            },
            "result": {
                "type": "eu-ai:MitigationAction",
                "action_taken": risk_mitigation,
            },
            "eu-ai:compliance_metadata": {
                "article": "12",
                "event_category": event_type,
                "severity_level": severity,
                "forensic_details": findings,
            },
        }

        # Append to a flat file for demonstration; in production, this would
        # stream to a tamper-evident audit log or SIEM.
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except IOError as e:
            # Fallback to stderr if file logging fails
            import sys

            print(f"COMPLIANCE_LOG_FAILURE: {e}", file=sys.stderr)

        return record


def log_compliance_event(
    event_type: str, severity: str, action: str, prompt: str, findings: Dict[str, Any]
):
    """Global utility for compliance logging."""
    logger = ComplianceLogger()
    return logger.log_event(event_type, severity, action, prompt, findings)
