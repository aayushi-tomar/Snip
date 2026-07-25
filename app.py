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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            clicked_at TEXT NOT NULL,
            referrer TEXT,
            user_agent TEXT
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


def log_click(code, referrer, user_agent):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO clicks (code, clicked_at, referrer, user_agent) VALUES (?, ?, ?, ?)",
        (code, datetime.now().isoformat(), referrer or "direct", user_agent or "unknown")
    )
    conn.commit()
    conn.close()


def get_click_stats(code):
    conn = sqlite3.connect(DB_FILE)
    total = conn.execute("SELECT COUNT(*) FROM clicks WHERE code = ?", (code,)).fetchone()[0]

    by_day = conn.execute("""
        SELECT substr(clicked_at, 1, 10) as day, COUNT(*) as count
        FROM clicks WHERE code = ?
        GROUP BY day ORDER BY day
    """, (code,)).fetchall()

    recent = conn.execute("""
        SELECT clicked_at, referrer, user_agent FROM clicks
        WHERE code = ? ORDER BY clicked_at DESC LIMIT 20
    """, (code,)).fetchall()

    conn.close()
    return {
        "total": total,
        "by_day": [{"day": d, "count": c} for d, c in by_day],
        "recent": [{"clicked_at": t, "referrer": r, "user_agent": u} for t, r, u in recent],
    }


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
                    resultDiv.innerHTML = "Shortened! <a href='" + data.short_url + "' target='_blank'>" + data.short_url + "</a>"
                        + " &middot; <a href='/stats/" + data.code + "' target='_blank'>view stats</a>";
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
        "short_url": f"{request.host_url}{code}"
    }), 201


@app.route("/<code>", methods=["GET"])
def resolve_endpoint(code):
    original_url = resolve(code)
    if not original_url:
        return jsonify({"error": "Code not found"}), 404

    log_click(code, request.referrer, request.headers.get("User-Agent"))
    return redirect(original_url)


@app.route("/stats/<code>", methods=["GET"])
def stats_endpoint(code):
    original_url = resolve(code)
    if not original_url:
        return jsonify({"error": "Code not found"}), 404

    stats = get_click_stats(code)

    days_labels = [row["day"] for row in stats["by_day"]]
    days_counts = [row["count"] for row in stats["by_day"]]

    recent_rows = "".join(
        f"<tr><td>{r['clicked_at']}</td><td>{r['referrer']}</td><td>{r['user_agent'][:60]}</td></tr>"
        for r in stats["recent"]
    ) or "<tr><td colspan='3'>No clicks yet</td></tr>"

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Stats for /{code}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        body {{ font-family: sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; }}
        h1 {{ color: #222; }}
        .stat-box {{ display: inline-block; padding: 15px 25px; background: #f0f0f0; border-radius: 8px; margin-right: 10px; }}
        .stat-number {{ font-size: 28px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #eee; font-size: 13px; }}
        th {{ background: #fafafa; }}
        a {{ color: #0066cc; }}
    </style>
</head>
<body>
    <p><a href="/">&larr; Back to shortener</a></p>
    <h1>Stats for /{code}</h1>
    <p>Original URL: <a href="{original_url}" target="_blank">{original_url}</a></p>

    <div class="stat-box">
        <div class="stat-number">{stats['total']}</div>
        <div>Total clicks</div>
    </div>

    <h3>Clicks over time</h3>
    <canvas id="clicksChart" height="100"></canvas>

    <h3>Recent clicks</h3>
    <table>
        <tr><th>When</th><th>Referrer</th><th>Browser / device</th></tr>
        {recent_rows}
    </table>

    <script>
        new Chart(document.getElementById('clicksChart'), {{
            type: 'bar',
            data: {{
                labels: {days_labels},
                datasets: [{{
                    label: 'Clicks per day',
                    data: {days_counts},
                    backgroundColor: '#4caf50'
                }}]
            }},
            options: {{ scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }} }}
        }});
    </script>
</body>
</html>
    """


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)