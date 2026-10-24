"""API key authentication for creating and deleting links."""

import pytest

from app.main import create_app, hash_api_key, parse_api_key_hashes
from tests.auth_helpers import AUTH, TEST_API_KEY


def create(client, headers=None):
    return client.post("/api/links", json={"url": "https://example.com"}, headers=headers or {})


def test_create_without_key_is_refused(anonymous_client):
    r = create(anonymous_client)
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Bearer")


def test_create_with_key_works(anonymous_client):
    assert create(anonymous_client, AUTH).status_code == 201


@pytest.mark.parametrize(
    "header",
    [
        "Bearer wrong-key",
        f"Basic {TEST_API_KEY}",
        f"bearer{TEST_API_KEY}",
        "Bearer ",
        "Bearer " + "a" * 5000,
        f"Bearer {TEST_API_KEY}x",
        f"Bearer {hash_api_key(TEST_API_KEY)}",  # the hash itself is not a key
    ],
)
def test_wrong_or_malformed_keys_are_refused(anonymous_client, header):
    assert create(anonymous_client, {"Authorization": header}).status_code == 401


def test_scheme_is_case_insensitive(anonymous_client):
    assert create(anonymous_client, {"Authorization": f"bEaReR {TEST_API_KEY}"}).status_code == 201


def test_delete_needs_a_key(client, anonymous_client):
    code = create(client).get_json()["code"]
    # The two clients use different databases, so check refusal on the anonymous one first.
    assert anonymous_client.delete(f"/api/links/{code}").status_code == 401
    assert client.delete(f"/api/links/{code}").status_code == 204


def test_reading_and_following_links_stay_public(client, tmp_path):
    code = create(client).get_json()["code"]
    del client.environ_base["HTTP_AUTHORIZATION"]
    assert client.get(f"/{code}").status_code == 302
    assert client.get(f"/api/links/{code}").status_code == 200
    assert client.get("/health").status_code == 200


def test_no_keys_configured_refuses_all_writes(tmp_path):
    app = create_app(db_path=str(tmp_path / "x.db"), rate_limit=100, api_key_hashes=[])
    c = app.test_client()
    assert create(c, AUTH).status_code == 401


def test_keys_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("API_KEY_HASHES", f" {hash_api_key('k1')} , {hash_api_key('k2').upper()} ")
    c = create_app(db_path=str(tmp_path / "env.db"), rate_limit=100).test_client()
    assert create(c, {"Authorization": "Bearer k1"}).status_code == 201
    assert create(c, {"Authorization": "Bearer k2"}).status_code == 201
    assert create(c, {"Authorization": "Bearer k3"}).status_code == 401


def test_a_mistyped_hash_stops_the_app_from_starting():
    with pytest.raises(ValueError):
        parse_api_key_hashes("not-a-sha256")


def test_failed_attempts_count_toward_the_rate_limit(tmp_path):
    app = create_app(db_path=str(tmp_path / "rl.db"), rate_limit=3, api_key_hashes=[hash_api_key("k")])
    c = app.test_client()
    for _ in range(3):
        assert create(c, {"Authorization": "Bearer guess"}).status_code == 401
    # Even the right key is now rate limited, so keys cannot be guessed quickly.
    assert create(c, {"Authorization": "Bearer k"}).status_code == 429


def test_keys_can_come_from_a_mounted_file(tmp_path, monkeypatch):
    secret = tmp_path / "hashes"
    secret.write_text(f"{hash_api_key('k1')}\n{hash_api_key('k2')}\n")
    monkeypatch.setenv("API_KEY_HASHES", hash_api_key("ignored-when-a-file-is-set"))
    monkeypatch.setenv("API_KEY_HASHES_FILE", str(secret))
    c = create_app(db_path=str(tmp_path / "f.db"), rate_limit=100).test_client()
    assert create(c, {"Authorization": "Bearer k2"}).status_code == 201
    assert create(c, {"Authorization": "Bearer ignored-when-a-file-is-set"}).status_code == 401


def test_a_missing_key_file_refuses_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("API_KEY_HASHES_FILE", str(tmp_path / "does-not-exist"))
    c = create_app(db_path=str(tmp_path / "m.db"), rate_limit=100).test_client()
    assert create(c, AUTH).status_code == 401
