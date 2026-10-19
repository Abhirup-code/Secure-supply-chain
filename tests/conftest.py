import pytest

from app.main import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "test.db"), rate_limit=1000)
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture()
def limited_client(tmp_path):
    app = create_app(db_path=str(tmp_path / "limited.db"), rate_limit=3)
    app.config["TESTING"] = True
    return app.test_client()
