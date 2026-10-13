import json

import httpx

from sentinela.ai.assistant import OllamaAssistant, build_prompt, parse_assessment
from sentinela.engine.models import Severity
from sentinela.engine.scanner import ScanOptions, scan_source


def _finding():
    source = (
        'from flask import request\nTOKEN = "Tk#9xQ2mLp7vR4"\ndef v(c):\n    c.execute("SELECT " + request.args["q"])\n'
    )
    findings = scan_source("a.py", source, "python", ScanOptions(use_bandit=False))
    return next(f for f in findings if f.cwe == "CWE-89")


def test_parse_valid_answer():
    payload = {
        "response": json.dumps(
            {
                "verdict": "false_positive",
                "confidence": "high",
                "rationale": "Linha 4 usa allowlist.",
                "suggested_severity": "low",
                "fix_explanation": "ok",
                "fix_code": "```python\nx = 1\n```",
            }
        )
    }
    result = parse_assessment(payload, model="llama3", current=Severity.CRITICAL)
    assert result.dismisses
    assert result.suggested_severity == "low"
    assert result.fix_code == "x = 1"


def test_parse_rejects_garbage():
    assert parse_assessment({"response": "não é json"}, model="m", current=Severity.HIGH) is None
    assert (
        parse_assessment(
            {"verdict": "talvez", "confidence": "high", "rationale": "x"}, model="m", current=Severity.HIGH
        )
        is None
    )


def test_same_severity_is_not_a_suggestion():
    payload = {"verdict": "true_positive", "confidence": "high", "rationale": "r", "suggested_severity": "critical"}
    assert parse_assessment(payload, model="m", current=Severity.CRITICAL).suggested_severity is None


def test_prompt_has_context_and_path_but_no_secret():
    prompt = build_prompt(_finding())
    assert "request.args" in prompt
    assert "Caminho do dado" in prompt
    assert "Tk#9xQ2mLp7vR4" not in prompt


def test_circuit_breaker(monkeypatch):
    calls = []

    def down(*args, **kwargs):
        calls.append(1)
        raise httpx.ConnectError("recusado")

    monkeypatch.setattr(httpx, "post", down)
    assistant = OllamaAssistant(base_url="http://ollama:11434", model="llama3")
    finding = _finding()
    assert assistant.assess(finding) is None
    assert assistant.assess(finding) is None
    assert len(calls) == 1
    assert not assistant.available


def test_calls_ollama_with_json_format(monkeypatch):
    sent = {}

    class Response:
        def raise_for_status(self):
            return self

        def json(self):
            return {"response": '{"verdict":"true_positive","confidence":"high","rationale":"Linha 4."}'}

    def fake_post(url, json=None, timeout=None):
        sent.update(json)
        return Response()

    monkeypatch.setattr(httpx, "post", fake_post)
    result = OllamaAssistant(base_url="http://x", model="llama3").assess(_finding())
    assert result.verdict == "true_positive"
    assert sent["format"] == "json"
    assert sent["options"]["temperature"] == 0
