from dataclasses import asdict

from sentinela.engine.scanner import ScanOptions, scan_source
from sentinela.gate import GatePolicy, evaluate
from sentinela.reporting.markdown import MARKER, pr_comment
from sentinela.reporting.sarif import to_sarif

SOURCE = "from flask import request\nimport pickle\ndef v(c):\n    c.execute('SELECT ' + request.args['q'])\n    pickle.loads(x)\n"


def _findings():
    out = []
    for f in scan_source("app.py", SOURCE, "python", ScanOptions(use_bandit=False)):
        out.append(
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "title": f.title,
                "language": f.language,
                "file_path": f.file_path,
                "line": f.line,
                "end_line": f.end_line,
                "column": f.column,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "message": f.message,
                "snippet": f.snippet,
                "engines": sorted(e.value for e in f.engines),
                "taint_path": [asdict(s) for s in f.taint_path],
                "remediation": f.remediation,
                "safe_example": f.safe_example,
                "references": f.references,
                "status": "open",
                "ai": None,
            }
        )
    return out


def test_sarif_structure_and_code_flows():
    sarif = to_sarif(_findings(), commit_sha="abc")
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    sql = next(r for r in run["results"] if r["ruleId"] == "python.taint.sql-injection")
    assert sql["level"] == "error"
    assert sql["codeFlows"][0]["threadFlows"][0]["locations"]
    assert run["tool"]["driver"]["rules"][sql["ruleIndex"]]["id"] == sql["ruleId"]
    assert "external/cwe/cwe-89" in run["tool"]["driver"]["rules"][sql["ruleIndex"]]["properties"]["tags"]


def test_sarif_suppresses_reviewed_findings():
    findings = _findings()
    findings[0]["status"] = "false_positive"
    result = to_sarif(findings)["runs"][0]["results"][0]
    assert result["suppressions"][0]["status"] == "accepted"


def test_pr_comment_collapses_ai_false_positives():
    findings = _findings()
    findings[1]["ai"] = {
        "verdict": "false_positive",
        "confidence": "high",
        "rationale": "arquivo confiável",
        "model": "llama3",
    }
    gate = evaluate(findings, GatePolicy()).to_dict()
    comment = pr_comment(findings, gate)
    assert comment.startswith(MARKER)
    assert "bloqueado" in comment
    assert "Prováveis falsos positivos" in comment
    assert comment.index(findings[0]["title"]) < comment.index("Prováveis falsos positivos")
