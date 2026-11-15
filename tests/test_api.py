import pytest
from fastapi.testclient import TestClient

from phishguard.api import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_SOURCE", "none")
    monkeypatch.setenv("PHISHGUARD_DB", f"sqlite:///{tmp_path}/api.db")
    with TestClient(app) as c:
        yield c


def test_check_flags_a_fake_domain(client):
    body = client.get("/api/check", params={"domain": "leumi-secure-login.xyz"}).json()
    assert body["brand"] == "Bank Leumi"
    assert body["severity"] == "high"
    assert body["reasons"]


def test_check_clears_the_real_domain(client):
    assert client.get("/api/check", params={"domain": "www.leumi.co.il"}).json()["score"] == 0


def test_check_rejects_missing_or_oversized_input(client):
    assert client.get("/api/check").status_code == 422
    assert client.get("/api/check", params={"domain": "a" * 300}).status_code == 422


def test_detections_and_stats(client):
    client.app.state.pipeline.handle("paypa1-verify.com")
    client.app.state.pipeline.handle("example.com")

    found = client.get("/api/detections").json()
    assert [d["domain"] for d in found] == ["paypa1-verify.com"]
    assert client.get("/api/detections", params={"min_score": 99}).json() == []
    assert client.get("/api/detections", params={"brand": "PayPal"}).json() == found

    stats = client.get("/api/stats").json()
    assert stats["processed"] == 2
    assert stats["detections"]["total"] == 1
    assert stats["detections"]["by_brand"] == {"PayPal": 1}


def test_dashboard_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "PhishGuard" in r.text
