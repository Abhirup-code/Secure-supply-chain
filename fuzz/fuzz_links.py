"""Fuzz test for the link API (Atheris, coverage-guided).

Feeds random and mutated input to the endpoints that handle untrusted data and checks the
security rules hold for every input, not just the cases written in the unit tests:

- the app never crashes (no 500 errors)
- a link is only stored if it is http(s), not too long, and not an internal address
- following a stored link redirects to exactly the stored URL
- arbitrary short codes never crash the lookup
- no random Authorization header is ever accepted as an API key

Run from the repository root: PYTHONPATH=. python fuzz/fuzz_links.py -max_total_time=60
"""

import json
import os
import secrets
import sys
import tempfile
from urllib.parse import urlparse

import atheris
from werkzeug.urls import iri_to_uri

with atheris.instrument_imports():
    from app.main import ALLOWED_SCHEMES, MAX_URL_LENGTH, create_app, hash_api_key, is_internal_host

_db_dir = tempfile.mkdtemp(prefix="fuzz-links-")
FUZZ_API_KEY = secrets.token_urlsafe(32)  # generated per run, never stored
APP = create_app(
    db_path=os.path.join(_db_dir, "fuzz.db"), rate_limit=10**9, api_key_hashes=[hash_api_key(FUZZ_API_KEY)]
)
APP.config["TESTING"] = True
CLIENT = APP.test_client()
CLIENT.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {FUZZ_API_KEY}"

# Building blocks that steer the fuzzer toward interesting URLs quickly.
SCHEMES = ["http", "https", "HTTP", "javascript", "data", "file", "ftp", "", "hTtPs"]
HOSTS = [
    "example.com",
    "localhost",
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "[::1]",
    "0.0.0.0",
    "metadata.google.internal",
    "a.localhost",
    "192.168.1.1",
    "[fe80::1]",
    "localhost\u3002",
    "\uff11\uff12\uff17.0.0.1",
    "b\u00fccher.example",
]


def check_create(url):
    resp = CLIENT.post("/api/links", json={"url": url})
    assert resp.status_code in (201, 400), f"unexpected {resp.status_code} for {url!r}"
    if resp.status_code != 201:
        return
    stored = resp.get_json()["url"]
    parsed = urlparse(stored)
    # Invariants: anything accepted must satisfy every validation rule.
    assert parsed.scheme.lower() in ALLOWED_SCHEMES, f"accepted bad scheme: {stored!r}"
    assert parsed.netloc, f"accepted URL with no host: {stored!r}"
    assert len(stored) <= MAX_URL_LENGTH, "accepted an over-long URL"
    assert not is_internal_host(parsed.hostname), f"accepted internal host: {stored!r}"
    follow = CLIENT.get(f"/{resp.get_json()['code']}")
    assert follow.status_code == 302
    # The Location header is the stored URL in its normalized, ASCII-safe form (Werkzeug
    # lowercases the scheme and percent-encodes unicode), and must point at the same host.
    location = follow.headers["Location"]
    assert location == iri_to_uri(stored), f"redirect {location!r} differs from stored {stored!r}"


def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 4)
    if choice == 0:
        # Structured URL built from risky parts plus fuzzed path
        url = (
            f"{fdp.PickValueInList(SCHEMES)}://{fdp.PickValueInList(HOSTS)}"
            f"{fdp.ConsumeUnicodeNoSurrogates(64)}"
        )
        check_create(url)
    elif choice == 1:
        # Completely free-form URL string
        check_create(fdp.ConsumeUnicodeNoSurrogates(4096))
    elif choice == 2:
        # Raw request body: malformed JSON, wrong types, binary data
        body = fdp.ConsumeBytes(512)
        resp = CLIENT.post("/api/links", data=body, content_type="application/json")
        assert resp.status_code in (201, 400), f"unexpected {resp.status_code} for raw body"
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if resp.status_code == 201:
            assert isinstance(parsed, dict), "accepted a body that is not a JSON object"
    elif choice == 3:
        # Random Authorization headers must never authenticate
        header = fdp.ConsumeUnicodeNoSurrogates(300)
        if header == f"Bearer {FUZZ_API_KEY}" or "\n" in header or "\r" in header:
            return
        try:
            resp = CLIENT.post(
                "/api/links", json={"url": "https://example.com"}, headers={"Authorization": header}
            )
        except ValueError:
            return  # the test client refuses header values that are not valid HTTP
        assert resp.status_code == 401, f"header {header!r} returned {resp.status_code}"
    else:
        # Arbitrary short codes for lookup, stats, and delete
        code = fdp.ConsumeUnicodeNoSurrogates(64).replace("/", "")
        for method, path in (
            ("get", f"/{code}"),
            ("get", f"/api/links/{code}"),
            ("delete", f"/api/links/{code}"),
        ):
            status = getattr(CLIENT, method)(path).status_code
            assert status < 500, f"{method.upper()} {path!r} returned {status}"


def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
