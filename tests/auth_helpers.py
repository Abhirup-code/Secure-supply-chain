"""The API key used in tests. Generated per test run, so no key is ever stored in the repository."""

import secrets

TEST_API_KEY = secrets.token_urlsafe(32)
AUTH = {"Authorization": f"Bearer {TEST_API_KEY}"}
