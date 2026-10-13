"""Exportação SARIF 2.1.0 — formato lido pelo GitHub code scanning e IDEs."""

from __future__ import annotations

from typing import Any

from sentinela import __version__

_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SUPPRESSED = {"false_positive", "accepted_risk", "fixed"}


def to_sarif(
    findings: list[dict[str, Any]], *, commit_sha: str | None = None, repository: str | None = None
) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule = rules.get(finding["rule_id"])
        if rule is None:
            rule = _rule(finding)
            rules[finding["rule_id"]] = rule
        elif float(_SECURITY_SEVERITY[finding["severity"]]) > float(rule["properties"]["security-severity"]):
            rule["properties"]["security-severity"] = _SECURITY_SEVERITY[finding["severity"]]
            rule["defaultConfiguration"]["level"] = _LEVEL[finding["severity"]]
        results.append(_result(finding))

    ordered = list(rules.values())
    index = {rule["id"]: i for i, rule in enumerate(ordered)}
    for result in results:
        result["ruleIndex"] = index[result["ruleId"]]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Sentinela",
                "semanticVersion": __version__,
                "informationUri": "https://github.com/GusRVPaulino/sast-devsecops-fiap",
                "rules": ordered,
            },
        },
        "results": results,
    }
    if commit_sha or repository:
        run["versionControlProvenance"] = [
            {k: v for k, v in {"repositoryUri": repository, "revisionId": commit_sha}.items() if v},
        ]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}


def _rule(finding: dict[str, Any]) -> dict[str, Any]:
    cwe = finding["cwe"]
    tags = ["security", f"external/cwe/{cwe.lower()}"]
    if finding.get("owasp"):
        tags.append("owasp/" + finding["owasp"].split(" ")[0].lower())
    help_md = finding.get("remediation", "")
    if finding.get("safe_example"):
        help_md += f"\n\n```{finding['language']}\n{finding['safe_example']}\n```"
    return {
        "id": finding["rule_id"],
        "name": finding["rule_id"].replace(".", "_").replace("-", "_"),
        "shortDescription": {"text": finding["title"]},
        "fullDescription": {"text": finding["message"]},
        "help": {"text": finding.get("remediation", ""), "markdown": help_md},
        "helpUri": (finding.get("references") or [None])[0] or "https://cwe.mitre.org",
        "defaultConfiguration": {"level": _LEVEL[finding["severity"]]},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[finding["severity"]],
            "precision": "high" if finding.get("confidence") == "high" else "medium",
        },
    }


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding["rule_id"],
        "level": _LEVEL[finding["severity"]],
        "message": {"text": finding["message"]},
        "locations": [_location(finding["file_path"], finding["line"], finding["end_line"], finding.get("column", 1))],
        "partialFingerprints": {"sentinela/v1": finding["fingerprint"]},
        "properties": {
            "severity": finding["severity"],
            "confidence": finding.get("confidence"),
            "engines": finding.get("engines", []),
            "status": finding.get("status", "open"),
        },
    }
    path = finding.get("taint_path") or []
    if path:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    **_location(finding["file_path"], step["line"], step["line"], 1),
                                    "message": {"text": f"{step['kind']}: {step['code']}"},
                                },
                            }
                            for step in path
                        ],
                    },
                ],
            },
        ]
    if finding.get("ai"):
        result["properties"]["ai"] = {
            k: finding["ai"].get(k) for k in ("verdict", "confidence", "rationale", "suggested_severity")
        }
    if finding.get("status") in _SUPPRESSED:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": finding.get("review_note") or finding["status"],
            },
        ]
    return result


def _location(path: str, line: int, end_line: int, column: int) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line, "endLine": max(line, end_line), "startColumn": max(1, column)},
        },
    }
