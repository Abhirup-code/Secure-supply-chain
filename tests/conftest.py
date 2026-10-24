import pytest

from app.main import create_app, hash_api_key
from tests.auth_helpers import AUTH, TEST_API_KEY


def make_client(tmp_path, name, rate_limit, authenticated=True):
    app = create_app(
        db_path=str(tmp_path / name), rate_limit=rate_limit, api_key_hashes=[hash_api_key(TEST_API_KEY)]
    )
    app.config["TESTING"] = True
    client = app.test_client()
    if authenticated:
        client.environ_base["HTTP_AUTHORIZATION"] = AUTH["Authorization"]
    return client


@pytest.fixture()
def client(tmp_path):
    """A client that sends a valid API key on every request."""
    return make_client(tmp_path, "test.db", 1000)


@pytest.fixture()
def anonymous_client(tmp_path):
    """A client with no API key."""
    return make_client(tmp_path, "anon.db", 1000, authenticated=False)


@pytest.fixture()
def limited_client(tmp_path):
    return make_client(tmp_path, "limited.db", 3)
