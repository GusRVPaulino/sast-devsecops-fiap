"""Modo fila: Celery em modo síncrono (eager) com o mesmo pipeline do Compose."""

import pytest


@pytest.fixture
def eager_queue(database, monkeypatch):
    from sentinela.config import get_settings
    from sentinela.worker.tasks import celery_app

    monkeypatch.setattr(get_settings(), "execution_mode", "queue")
    monkeypatch.setattr(get_settings(), "ai_enabled", True)
    monkeypatch.setattr(get_settings(), "ollama_url", "http://127.0.0.1:9")  # IA fora do ar
    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)
    monkeypatch.setattr(celery_app.conf, "task_eager_propagates", True)


def test_queue_pipeline_with_ai_offline_still_completes(eager_queue):
    from fastapi.testclient import TestClient

    from sentinela.api.app import app

    client = TestClient(app)
    body = {"project": "fila", "files": [{"path": "a.py", "content": "import pickle\npickle.loads(x)\neval(y)\n"}]}
    scan = client.post("/api/scans", json=body).json()
    final = client.get(f"/api/scans/{scan['id']}").json()
    assert final["status"] == "completed"
    assert final["counts"]["total"] == 2
    assert all(f["ai"] is None for f in client.get(f"/api/scans/{scan['id']}/findings").json())


def test_ai_assessment_is_stored(database, monkeypatch):
    from sentinela import services
    from sentinela.ai.assistant import AIAssessment
    from sentinela.storage.db import session_scope

    class FakeAssistant:
        available = True

        def assess(self, finding):
            return AIAssessment("false_positive", "high", "arquivo gerado no build", "low", "nada", "", "fake")

    with session_scope() as session:
        scan_id = services.create_scan(session, project="ia", files=[("a.py", "import pickle\npickle.loads(x)\n")]).id
    services.process_inline(scan_id, assistant=FakeAssistant())
    with session_scope() as session:
        (finding,) = services.scan_findings(session, scan_id)
    assert finding["ai"]["verdict"] == "false_positive"
    assert finding["status"] == "open"  # IA não muda status
