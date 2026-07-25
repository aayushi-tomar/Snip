"""
URL Shortener - complete working version
Run with: python app.py
Then visit http://localhost:5000/shorten (POST) or http://localhost:5000/<code> (GET)
"""

import random
import string
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)
DB_FILE = "urls.db"


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


def is_safe_url(url):
    """
    Placeholder safety check. Swap this out for a real call to the
    Google Safe Browsing API or VirusTotal API once you have a key.
    For now it blocks a small hardcoded list so the feature is demoable
    without needing an API key today.
    """
    known_bad_patterns = ["malware-test.com", "phishing-test.com"]
    return not any(bad in url for bad in known_bad_patterns)


def shorten(url):
    if not is_valid_url(url):
        raise ValueError("Invalid URL")

    if not is_safe_url(url):
        raise ValueError("URL flagged as unsafe and cannot be shortened")

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