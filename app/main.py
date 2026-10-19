"""secure-supply-chain: a small link shortener built to demonstrate a secure delivery pipeline.

Security choices in the app itself:
- Only http and https URLs are accepted, which blocks javascript: and data: links
  (stored XSS / open redirect abuse).
- Short codes come from the `secrets` module, so they cannot be guessed.
- All SQL uses parameterized queries (no string formatting), which prevents SQL injection.
- Security headers are added to every response, and debug mode is never enabled.
"""

import ipaddress
import os
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlparse

from flask import Flask, abort, g, jsonify, redirect, request

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}


def is_internal_host(hostname):
    """Return True if a link points at a loopback, private, link-local, or reserved address.

    This stops short links being used to send people to internal systems or the cloud
    metadata service (169.254.169.254). Hostnames are not resolved; only names and IP
    literals are checked.
    """
    host = (hostname or "").strip(".").lower()
    if host in BLOCKED_HOSTNAMES or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


class RateLimiter:
    """Fixed-window rate limiter kept in memory, keyed by client IP.

    Each gunicorn worker keeps its own counts, so the effective limit is per worker.
    That is enough to stop simple abuse in a demo; a shared store such as Redis would
    be used in production.
    """

    def __init__(self, limit, window_seconds=60):
        self.limit = limit
        self.window = window_seconds
        self._hits = {}
        self._lock = threading.Lock()

    def check(self, key):
        """Record a request and return (allowed, seconds_until_reset)."""
        now = time.monotonic()
        with self._lock:
            start, count = self._hits.get(key, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            count += 1
            self._hits[key] = (start, count)
            retry_after = max(1, int(self.window - (now - start)))
            return count <= self.limit, retry_after


def create_app(db_path=None, rate_limit=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.environ.get("DB_PATH", "/data/links.db")
    limit = rate_limit if rate_limit is not None else int(os.environ.get("RATE_LIMIT_PER_MINUTE", "30"))
    limiter = RateLimiter(limit=limit)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().execute(
            "CREATE TABLE IF NOT EXISTS links ("
            "code TEXT PRIMARY KEY, url TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0)"
        )
        get_db().commit()

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/api/links")
    def create_link():
        allowed, retry_after = limiter.check(request.remote_addr or "unknown")
        if not allowed:
            resp = jsonify(error="rate limit exceeded, try again later")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()
        if not url:
            return jsonify(error="url is required"), 400
        if len(url) > MAX_URL_LENGTH:
            return jsonify(error="url too long"), 400
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.netloc:
            return jsonify(error="only http and https URLs are allowed"), 400
        if is_internal_host(parsed.hostname):
            return jsonify(error="links to internal or private addresses are not allowed"), 400
        db = get_db()
        for _ in range(5):
            code = secrets.token_urlsafe(6)
            try:
                db.execute("INSERT INTO links (code, url) VALUES (?, ?)", (code, url))
                db.commit()
                return jsonify(code=code, url=url, short=f"/{code}"), 201
            except sqlite3.IntegrityError:
                continue
        return jsonify(error="could not allocate a code"), 503

    @app.get("/api/links/<code>")
    def link_stats(code):
        row = get_db().execute("SELECT code, url, hits FROM links WHERE code = ?", (code,)).fetchone()
        if row is None:
            return jsonify(error="not found"), 404
        return jsonify(dict(row))

    @app.delete("/api/links/<code>")
    def delete_link(code):
        db = get_db()
        cur = db.execute("DELETE FROM links WHERE code = ?", (code,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify(error="not found"), 404
        return "", 204

    @app.get("/<code>")
    def follow(code):
        db = get_db()
        row = db.execute("SELECT url FROM links WHERE code = ?", (code,)).fetchone()
        if row is None:
            abort(404)
        db.execute("UPDATE links SET hits = hits + 1 WHERE code = ?", (code,))
        db.commit()
        return redirect(row["url"], code=302)

    return app
