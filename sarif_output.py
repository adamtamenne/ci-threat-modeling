"""SARIF 2.1.0 output for scan_diff.py.

Converts scan_diff findings into the SARIF format consumed by
GitHub Code Scanning (github/codeql-action/upload-sarif).

Usage in scan_diff.py:
    from sarif_output import generate_sarif

    # after building the findings list:
    if args.sarif_out:
        sarif = generate_sarif(findings)
        Path(args.sarif_out).write_text(json.dumps(sarif, indent=2))
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

TOOL_NAME = "scan_diff"
TOOL_VERSION = "1.1.0"
TOOL_URI = "https://github.com/adamtamenne/ci-threat-modeling"

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SEVERITY_MAP: dict[str, str] = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}


def _normalize(finding: Any) -> dict:
    """Accept both dataclass instances and plain dicts."""
    if isinstance(finding, dict):
        return finding
    return asdict(finding)


def _build_rule(f: dict) -> dict:
    """Build a SARIF rule descriptor from a finding."""
    rule: dict[str, Any] = {
        "id": f["pattern_id"],
        "name": f["pattern_name"],
        "shortDescription": {"text": f["pattern_name"]},
        "fullDescription": {"text": f["description"]},
        "properties": {"tags": list(f.get("stride", []))},
    }
    cwe = f.get("cwe", "")
    if cwe:
        cwe_id = cwe.replace("CWE-", "")
        rule["helpUri"] = (
            f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        )
    return rule


def _build_result(f: dict) -> dict:
    """Build a SARIF result from a finding."""
    result: dict[str, Any] = {
        "ruleId": f["pattern_id"],
        "level": _SEVERITY_MAP.get(f["severity"], "warning"),
        "message": {
            "text": (
                f"{f['pattern_name']}: {f['description']}\n\n"
                f"Remediation: {f['remediation']}"
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f["file"],
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": f["line"]},
                },
            }
        ],
        "properties": {"stride": list(f.get("stride", []))},
    }

    cwe = f.get("cwe", "")
    if cwe:
        result["taxa"] = [
            {
                "toolComponent": {"name": "cwe"},
                "id": cwe.replace("CWE-", ""),
            }
        ]
    return result


def generate_sarif(findings: list) -> dict:
    """Convert scan_diff findings to a SARIF 2.1.0 document.

    Args:
        findings: List of Finding dataclass instances or dicts with keys:
            pattern_id, pattern_name, description, severity, remediation,
            file, line, stride (list[str]), cwe (str).

    Returns:
        A dict ready for json.dumps() that conforms to SARIF 2.1.0.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for raw in findings:
        f = _normalize(raw)
        rule_id = f["pattern_id"]

        if rule_id not in rules:
            rules[rule_id] = _build_rule(f)

        results.append(_build_result(f))

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            }
        ],
    }
