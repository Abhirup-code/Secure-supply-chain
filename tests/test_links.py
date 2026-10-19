"""Functional and security tests for the link shortener."""

import time

import pytest

from app.main import RateLimiter


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


@pytest.mark.parametrize(
    "internal_url",
    [
        "http://localhost/admin",
        "http://LOCALHOST:8080",
        "http://app.localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://192.168.1.1/router",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://0.0.0.0/",
        "http://[::1]/",
    ],
)
def test_internal_and_private_addresses_rejected(client, internal_url):
    r = create(client, internal_url)
    assert r.status_code == 400
    assert "internal" in r.get_json()["error"]


def test_public_ip_and_domain_still_allowed(client):
    assert create(client, "https://8.8.8.8/").status_code == 201
    assert create(client, "https://example.com/path?q=1").status_code == 201


def test_rate_limit_blocks_after_limit(limited_client):
    for _ in range(3):
        assert create(limited_client, "https://example.com").status_code == 201
    r = create(limited_client, "https://example.com")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert "rate limit" in r.get_json()["error"]


def test_rate_limit_does_not_affect_reads(limited_client):
    code = create(limited_client, "https://example.com").get_json()["code"]
    for _ in range(3):
        create(limited_client, "https://example.com")
    assert limited_client.get(f"/{code}").status_code == 302
    assert limited_client.get(f"/api/links/{code}").status_code == 200


def test_rate_limit_window_resets():
    limiter = RateLimiter(limit=1, window_seconds=0.05)
    assert limiter.check("1.2.3.4")[0] is True
    assert limiter.check("1.2.3.4")[0] is False
    time.sleep(0.06)
    assert limiter.check("1.2.3.4")[0] is True


def test_rate_limit_is_per_client():
    limiter = RateLimiter(limit=1)
    assert limiter.check("1.1.1.1")[0] is True
    assert limiter.check("2.2.2.2")[0] is True
    assert limiter.check("1.1.1.1")[0] is False
