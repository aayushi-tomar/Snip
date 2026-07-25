"""
URL Shortener - final version
Run with: python app.py

Requires a Google Safe Browsing API key set as an environment variable
GOOGLE_SAFE_BROWSING_API_KEY (see README for how to get one - it's free).
"""

import os
import random
import string
import sqlite3
from datetime import datetime

import requests
from flask import Flask, request, jsonify, redirect
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
DB_FILE = "urls.db"
SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# In-memory cache so we don't re-check the same URL against the API repeatedly.
# Format: { "https://example.com": True/False }
_safety_cache = {}


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            code TEXT PRIMARY KEY,
            original_url TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def generate_code(length=6):
    pool = string.ascii_letters + string.digits
    return "".join(random.choices(pool, k=length))


def is_valid_url(url):
    return isinstance(url, str) and (url.startswith("http://") or url.startswith("https://")) and len(url) > 10


def code_exists(code):
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT 1 FROM urls WHERE code = ?", (code,)).fetchone()
    conn.close()
    return row is not None


def check_safe_browsing_api(url):
    """
    Calls the real Google Safe Browsing API.
    Returns True if the URL is safe, False if it's flagged.
    Raises an exception if the API call itself fails (network error, bad key, etc)
    so the caller can decide how to handle that separately from "URL is unsafe".
    """
    if not SAFE_BROWSING_API_KEY:
        raise RuntimeError("GOOGLE_SAFE_BROWSING_API_KEY is not set")

    payload = {
        "client": {"clientId": "snip-url-shortener", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    response = requests.post(
        SAFE_BROWSING_URL,
        params={"key": SAFE_BROWSING_API_KEY},
        json=payload,
        timeout=5,
    )
    response.raise_for_status()  # raises if the API call itself failed (bad key, 4xx/5xx, etc)

    data = response.json()
    # If "matches" is present and non-empty, Google found a threat match -> unsafe.
    return "matches" not in data or not data["matches"]


def is_safe_url(url):
    """
    Checks a URL against the Google Safe Browsing API, with caching.

    Fallback behavior (documented decision, "fail closed"):
    if the API call itself fails for any reason (network issue, bad key,
    rate limit, timeout), we treat the URL as UNSAFE and reject it, rather
    than letting it through unchecked. This is more cautious but means the
    shortener could reject legitimate URLs during an API outage - a
    deliberate reliability/availability tradeoff, chosen here because
    "silently letting a malicious link through" is worse than
    "occasionally block a legitimate one during an outage".
    """
    if url in _safety_cache:
        return _safety_cache[url]

    try:
        safe = check_safe_browsing_api(url)
    except Exception:
        # Fail closed: if we can't verify safety, don't allow it through.
        safe = False

    _safety_cache[url] = safe
    return safe


def shorten(url):
    if not is_valid_url(url):
        raise ValueError("Invalid URL")

    if not is_safe_url(url):
        raise ValueError("URL flagged as unsafe (or safety check unavailable) and cannot be shortened")

    code = generate_code()
    while code_exists(code):
        code = generate_code()

    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO urls (code, original_url, created_at) VALUES (?, ?, ?)",
        (code, url, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return code


def resolve(code):
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT original_url FROM urls WHERE code = ?", (code,)).fetchone()
    conn.close()
    return row[0] if row else None


# Initialize the database at import time so this also works when run
# under a production server like Gunicorn (which never executes the
# `if __name__ == "__main__":` block below).
init_db()


@app.route("/", methods=["GET"])
def home():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Snip - URL Shortener</title>
    <style>
        body { font-family: sans-serif; max-width: 500px; margin: 80px auto; padding: 0 20px; }
        h1 { color: #222; }
        input[type=text] { width: 100%; padding: 10px; font-size: 16px; box-sizing: border-box; margin-bottom: 10px; }
        button { padding: 10px 20px; font-size: 16px; cursor: pointer; }
        #result { margin-top: 20px; padding: 15px; border-radius: 6px; }
        .success { background: #e6ffe6; border: 1px solid #4caf50; }
        .error { background: #ffe6e6; border: 1px solid #f44336; }
        a { word-break: break-all; }
    </style>
</head>
<body>
    <h1>Snip — URL Shortener</h1>
    <p>Paste a long URL below and shorten it.</p>
    <input type="text" id="urlInput" placeholder="https://example.com/some/very/long/url">
    <button onclick="shortenUrl()">Shorten</button>
    <div id="result"></div>

    <script>
        async function shortenUrl() {
            const url = document.getElementById('urlInput').value;
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = "Working...";
            resultDiv.className = "";

            try {
                const response = await fetch('/shorten', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();

                if (response.ok) {
                    resultDiv.className = "success";
                    resultDiv.innerHTML = "Shortened! <a href='" + data.short_url + "' target='_blank'>" + data.short_url + "</a>";
                } else {
                    resultDiv.className = "error";
                    resultDiv.innerHTML = "Error: " + data.error;
                }
            } catch (err) {
                resultDiv.className = "error";
                resultDiv.innerHTML = "Something went wrong: " + err;
            }
        }
    </script>
</body>
</html>
    """


@app.route("/shorten", methods=["POST"])
def shorten_endpoint():
    data = request.get_json(silent=True) or {}
    url = data.get("url")

    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400

    try:
        code = shorten(url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({
        "code": code,
        "short_url": f"http://localhost:5000/{code}"
    }), 201


@app.route("/<code>", methods=["GET"])
def resolve_endpoint(code):
    original_url = resolve(code)
    if not original_url:
        return jsonify({"error": "Code not found"}), 404
    return redirect(original_url)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)