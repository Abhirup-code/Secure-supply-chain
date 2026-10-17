"""Functional and security tests for the link shortener."""

import pytest


def create(client, url):
    return client.post("/api/links", json={"url": url})


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_create_and_follow_link(client):
    r = create(client, "https://example.com/page")
    assert r.status_code == 201
    code = r.get_json()["code"]
    follow = client.get(f"/{code}")
    assert follow.status_code == 302
    assert follow.headers["Location"] == "https://example.com/page"


def test_hits_are_counted(client):
    code = create(client, "https://example.com").get_json()["code"]
    client.get(f"/{code}")
    client.get(f"/{code}")
    assert client.get(f"/api/links/{code}").get_json()["hits"] == 2


def test_unknown_code_returns_404(client):
    assert client.get("/doesnotexist").status_code == 404
    assert client.get("/api/links/doesnotexist").status_code == 404


def test_missing_url_rejected(client):
    assert client.post("/api/links", json={}).status_code == 400


@pytest.mark.parametrize(
    "bad_url",
    [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "ftp://example.com",
        "not a url",
        "https://",
    ],
)
def test_dangerous_or_invalid_urls_rejected(client, bad_url):
    r = create(client, bad_url)
    assert r.status_code == 400


def test_overlong_url_rejected(client):
    assert create(client, "https://example.com/" + "a" * 3000).status_code == 400


def test_sql_injection_attempt_is_harmless(client):
    code = create(client, "https://example.com").get_json()["code"]
    r = client.get("/api/links/' OR '1'='1")
    assert r.status_code == 404
    assert client.get(f"/api/links/{code}").status_code == 200


def test_codes_are_unique_and_unpredictable(client):
    codes = {create(client, "https://example.com").get_json()["code"] for _ in range(50)}
    assert len(codes) == 50
    assert all(len(c) >= 8 for c in codes)


def test_security_headers_on_every_response(client):
    for path in ["/health", "/doesnotexist"]:
        r = client.get(path)
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_delete_link(client):
    code = create(client, "https://example.com").get_json()["code"]
    assert client.delete(f"/api/links/{code}").status_code == 204
    assert client.get(f"/{code}").status_code == 404
    assert client.get(f"/api/links/{code}").status_code == 404


def test_delete_unknown_link_returns_404(client):
    assert client.delete("/api/links/doesnotexist").status_code == 404
