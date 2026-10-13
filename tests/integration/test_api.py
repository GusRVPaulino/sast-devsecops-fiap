import io
import zipfile

VULN = "from flask import request\ndef v(c):\n    c.execute('SELECT ' + request.args['q'])\n"


def _scan(client, files, project="loja"):
    response = client.post("/api/scans", json={"project": project, "files": files, "commit_sha": "abc1234"})
    assert response.status_code == 202
    return response.json()


def test_full_flow_scan_findings_gate_reports(client):
    scan = _scan(
        client,
        [{"path": "app/views.py", "content": VULN}, {"path": "web/a.js", "content": "el.innerHTML = location.hash;"}],
    )
    assert scan["status"] == "completed"
    assert scan["gate"]["status"] == "failed"
    assert scan["languages"] == {"python": 1, "javascript": 1}

    findings = client.get(f"/api/scans/{scan['id']}/findings").json()
    assert {f["rule_id"] for f in findings} == {"python.taint.sql-injection", "javascript.taint.xss"}
    assert client.get(f"/api/scans/{scan['id']}/gate").json()["status"] == "failed"
    assert client.get(f"/api/scans/{scan['id']}/sarif").json()["version"] == "2.1.0"
    assert "Sentinela" in client.get(f"/api/scans/{scan['id']}/report.md").text


def test_review_persists_across_scans_by_fingerprint(client):
    first = _scan(client, [{"path": "app/views.py", "content": VULN}])
    finding = client.get(f"/api/scans/{first['id']}/findings").json()[0]
    updated = client.patch(
        f"/api/findings/{finding['id']}",
        json={"status": "accepted_risk", "note": "endpoint interno", "actor": "ana"},
    ).json()
    assert updated["history"][0]["to"] == "accepted_risk"

    # O código ganhou linhas acima: mesmo achado, outra linha, decisão mantida.
    second = _scan(client, [{"path": "app/views.py", "content": "# novo\n\n" + VULN}])
    again = client.get(f"/api/scans/{second['id']}/findings").json()[0]
    assert again["line"] == finding["line"] + 2
    assert again["status"] == "accepted_risk"
    assert second["gate"]["status"] == "passed"


def test_invalid_review_status(client):
    scan = _scan(client, [{"path": "a.py", "content": VULN}])
    finding = client.get(f"/api/scans/{scan['id']}/findings").json()[0]
    assert client.patch(f"/api/findings/{finding['id']}", json={"status": "ignorar"}).status_code == 422


def test_zip_upload_skips_vendor_and_traversal(client):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("src/app.py", VULN)
        archive.writestr("node_modules/lib/index.js", "eval(x)")
        archive.writestr("../../etc/evil.py", "import pickle\npickle.loads(x)")
        archive.writestr("README.md", "# doc")
    response = client.post(
        "/api/scans/upload",
        data={"project": "zip"},
        files={"archive": ("codigo.zip", buffer.getvalue(), "application/zip")},
    )
    assert response.status_code == 202
    scan = response.json()
    paths = {f["file_path"] for f in client.get(f"/api/scans/{scan['id']}/findings").json()}
    assert paths == {"src/app.py", "etc/evil.py"}


def test_metrics_and_projects(client):
    _scan(client, [{"path": "a.py", "content": VULN}], project="m")
    metrics = client.get("/api/projects/m/metrics").json()
    assert metrics["totals"]["critical"] == 1
    assert metrics["top_files"][0]["file"] == "a.py"
    assert metrics["owasp"][0]["category"].startswith("A03")
    assert any(p["name"] == "m" for p in client.get("/api/projects").json())


def test_rules_catalog_covers_three_languages(client):
    languages = {rule["language"] for rule in client.get("/api/rules").json()}
    assert {"python", "javascript", "java"} <= languages


def test_api_token_protects_writes(client, monkeypatch):
    from sentinela.config import get_settings

    monkeypatch.setattr(get_settings(), "api_token", "segredo")
    body = {"project": "p", "files": [{"path": "a.py", "content": "x = 1"}]}
    assert client.post("/api/scans", json=body).status_code == 401
    assert client.post("/api/scans", json=body, headers={"X-API-Token": "segredo"}).status_code == 202


def test_dashboard_is_served(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "Sentinela" in page.text
