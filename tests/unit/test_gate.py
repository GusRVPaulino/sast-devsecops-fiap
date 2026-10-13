from sentinela.gate import GatePolicy, evaluate


def _f(severity="critical", engines=("taint",), status="open", path="app.py", rule="r"):
    return {
        "severity": severity,
        "engines": list(engines),
        "status": status,
        "file_path": path,
        "rule_id": rule,
        "line": 1,
        "fingerprint": f"{rule}-{severity}-{path}",
    }


def test_taint_evidence_blocks():
    assert evaluate([_f()], GatePolicy()).status == "failed"


def test_single_pattern_only_warns():
    decision = evaluate([_f(severity="high", engines=("rule",))], GatePolicy())
    assert decision.status == "warned"
    assert decision.passed


def test_two_engines_block():
    assert evaluate([_f(severity="high", engines=("rule", "bandit"))], GatePolicy()).status == "failed"


def test_below_threshold_passes():
    assert evaluate([_f(severity="medium")], GatePolicy()).status == "passed"


def test_reviewer_decision_removes_from_gate():
    assert evaluate([_f(status="false_positive")], GatePolicy()).status == "passed"


def test_ai_verdict_never_unblocks():
    finding = _f()
    finding["ai"] = {"verdict": "false_positive", "confidence": "high"}
    assert evaluate([finding], GatePolicy()).status == "failed"


def test_ignore_paths_and_rules():
    policy = GatePolicy.from_dict({"gate": {"ignore_paths": ["tests/*"], "ignore_rules": ["legacy.*"]}})
    findings = [_f(path="tests/x.py"), _f(rule="legacy.old")]
    assert evaluate(findings, policy).status == "passed"


def test_policy_without_strong_evidence_blocks_any():
    policy = GatePolicy.from_dict({"gate": {"fail_on": "medium", "require_strong_evidence": False}})
    assert evaluate([_f(severity="medium", engines=("rule",))], policy).status == "failed"
