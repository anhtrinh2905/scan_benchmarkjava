"""Scan-result normalizer (flow/05-contract.md v1.1 increment).

Maps semgrep SARIF and Metis bench_summary.json into the flat `Alert` schema and
appends them to the knowledge-base JSONL. Read-only except `append_alerts`
(writes `data/kb/alerts.jsonl`) — no `st.*`; any future UI card consumes FROM here.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent.parent
KB_DIR = ROOT / "data" / "kb"
KB_ALERTS_PATH = KB_DIR / "alerts.jsonl"

SEVERITIES = {"critical", "high", "medium", "low", "info"}
DEFAULT_SEVERITY = "medium"

# SARIF `level` (when present) -> Alert.severity
_SARIF_LEVEL_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

_CWE_RE = re.compile(r"CWE-\d+")


@dataclass
class Alert:
    tool: Literal["semgrep", "metis"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    file_or_url: str
    title: str
    description: str
    rule_id: str | None
    cwe: str | None
    line: int | None
    source_path: str


def _sarif_severity(rule_id: str, message: str, level: str | None) -> str:
    """SARIF here carries no per-result `level` for this repo's rule set, so this
    repo's rules (weak-prng, insecure-cookie) fall through to the documented
    default. `level` is honored when a future rule set does set it."""
    if level in _SARIF_LEVEL_SEVERITY:
        return _SARIF_LEVEL_SEVERITY[level]
    return DEFAULT_SEVERITY


def normalize_sarif(sarif_path: Path, tool: str) -> list[Alert]:
    data = json.loads(Path(sarif_path).read_text())
    alerts: list[Alert] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            message = result.get("message", {}).get("text", "")
            location = result["locations"][0]["physicalLocation"]
            uri = location["artifactLocation"]["uri"]
            line = location.get("region", {}).get("startLine")
            cwe_match = _CWE_RE.search(message)
            name_parts = (rule_id or "").split(".")
            title = ".".join(name_parts[-2:]) if len(name_parts) >= 2 else (rule_id or message[:80])
            alerts.append(
                Alert(
                    tool=tool,
                    severity=_sarif_severity(rule_id or "", message, result.get("level")),
                    file_or_url=uri,
                    title=title,
                    description=message,
                    rule_id=rule_id,
                    cwe=cwe_match.group(0) if cwe_match else None,
                    line=line,
                    source_path=str(sarif_path),
                )
            )
    return alerts


def normalize_bench_summary(summary_path: Path) -> list[Alert]:
    data = json.loads(Path(summary_path).read_text())
    alerts: list[Alert] = []
    for test_name, findings in data.get("findings", {}).items():
        file_or_url = f"src/main/java/org/owasp/benchmark/testcode/{test_name}.java"
        for finding in findings:
            severity = str(finding.get("severity", DEFAULT_SEVERITY)).lower()
            if severity not in SEVERITIES:
                severity = DEFAULT_SEVERITY
            alerts.append(
                Alert(
                    tool="metis",
                    severity=severity,
                    file_or_url=file_or_url,
                    title=finding.get("issue") or f"metis finding ({test_name})",
                    description=finding.get("reasoning") or finding.get("issue") or "",
                    rule_id=None,
                    cwe=finding.get("cwe_raw"),
                    line=finding.get("line"),
                    source_path=str(summary_path),
                )
            )
    return alerts


def append_alerts(alerts: list[Alert], out_path: Path = KB_ALERTS_PATH) -> int:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a") as f:
        for alert in alerts:
            f.write(json.dumps(asdict(alert)) + "\n")
    return len(alerts)
