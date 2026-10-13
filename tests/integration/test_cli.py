import json

from sentinela.cli import main


def test_cli_blocks_and_writes_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(
        "from flask import request\ndef v(c):\n    c.execute('SELECT ' + request.args['q'])\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("eval(a)")
    code = main(["scan", ".", "--sarif", "out.sarif", "--markdown", "out.md", "--json", "out.json", "--quiet"])
    assert code == 1
    data = json.loads((tmp_path / "out.json").read_text())
    assert data["gate"]["status"] == "failed"
    assert [f["file_path"] for f in data["findings"]] == ["app.py"]
    assert json.loads((tmp_path / "out.sarif").read_text())["version"] == "2.1.0"
    assert "bloqueado" in (tmp_path / "out.md").read_text()


def test_cli_policy_and_no_fail(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(x)\n")
    (tmp_path / ".sentinela.yml").write_text("gate:\n  fail_on: critical\n")
    assert main(["scan", ".", "--quiet", "--no-bandit"]) == 0
    (tmp_path / ".sentinela.yml").write_text("gate:\n  fail_on: high\n  require_strong_evidence: false\n")
    assert main(["scan", ".", "--quiet", "--no-bandit"]) == 1
    assert main(["scan", ".", "--quiet", "--no-bandit", "--no-fail"]) == 0


def test_cli_nothing_to_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "notes.txt").write_text("nada")
    assert main(["scan", "."]) == 0
