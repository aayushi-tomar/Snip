"""
URL Shortener - Snip
Run with: python app.py

Requires a Google Safe Browsing API key set as an environment variable
GOOGLE_SAFE_BROWSING_API_KEY (see README for how to get one - it's free).
"""

import os
import random
import string
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, redirect
from dotenv import load_dotenv
import sqlite3

load_dotenv()

app = Flask(__name__)
DB_FILE = "urls.db"
SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_safety_cache = {}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

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


# Initialize the database at import time so this also works when run
# under a production server like Gunicorn (which never executes the
# `if __name__ == "__main__":` block below).
init_db()


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

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
    Raises an exception if the API call itself fails so the caller can
    decide how to handle that separately from "URL is unsafe".
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
        SAFE_BROWSING_URL, params={"key": SAFE_BROWSING_API_KEY}, json=payload, timeout=5
    )
    response.raise_for_status()
    data = response.json()
    return "matches" not in data or not data["matches"]


def is_safe_url(url):
    """
    Fail-closed: if the safety API call itself fails for any reason
    (network issue, bad key, rate limit, timeout), the URL is treated as
    unsafe and rejected rather than let through unchecked.
    """
    if url in _safety_cache:
        return _safety_cache[url]
    try:
        safe = check_safe_browsing_api(url)
    except Exception:
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
        (code, datetime.now().isoformat(), referrer or "", user_agent or "")
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Stats: per-link and site-wide
# ---------------------------------------------------------------------------

def get_click_stats(code):
    conn = sqlite3.connect(DB_FILE)
    total = conn.execute("SELECT COUNT(*) FROM clicks WHERE code = ?", (code,)).fetchone()[0]
    by_day = conn.execute("""
        SELECT substr(clicked_at, 1, 10) as day, COUNT(*) as count
        FROM clicks WHERE code = ? GROUP BY day ORDER BY day
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


def _classify_device(user_agent):
    ua = (user_agent or "").lower()
    if "tablet" in ua or "ipad" in ua:
        return "Tablet"
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "Mobile"
    return "Desktop"


def _referrer_label(referrer):
    if not referrer:
        return "Direct"
    try:
        host = urlparse(referrer).netloc.lower().replace("www.", "")
    except Exception:
        return "Other"
    if not host:
        return "Direct"
    if "google" in host:
        return "Google"
    if "twitter" in host or "x.com" in host:
        return "Twitter"
    if "github" in host:
        return "GitHub"
    if "reddit" in host:
        return "Reddit"
    if "facebook" in host:
        return "Facebook"
    if "linkedin" in host:
        return "LinkedIn"
    return "Other"


def get_dashboard_stats():
    conn = sqlite3.connect(DB_FILE)
    total_links = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
    total_clicks = conn.execute("SELECT COUNT(*) FROM clicks").fetchone()[0]

    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    this_week = conn.execute("SELECT COUNT(*) FROM urls WHERE created_at >= ?", (week_ago,)).fetchone()[0]

    rows = conn.execute("""
        SELECT u.code, u.original_url, u.created_at, COUNT(c.id) as clicks
        FROM urls u LEFT JOIN clicks c ON u.code = c.code
        GROUP BY u.code ORDER BY u.created_at DESC LIMIT 6
    """).fetchall()
    conn.close()

    avg_clicks = round(total_clicks / total_links) if total_links else 0

    recent_links = [
        {"code": code, "url": url, "created_at": created[:10], "clicks": clicks}
        for code, url, created, clicks in rows
    ]

    return {
        "total_links": total_links,
        "total_clicks": total_clicks,
        "this_week": this_week,
        "avg_clicks": avg_clicks,
        "recent_links": recent_links,
    }


def get_analytics_overview():
    conn = sqlite3.connect(DB_FILE)
    total_clicks = conn.execute("SELECT COUNT(*) FROM clicks").fetchone()[0]
    unique_links = conn.execute("SELECT COUNT(DISTINCT code) FROM clicks").fetchone()[0]

    # last 7 days, zero-filled
    today = datetime.now().date()
    days = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    day_strs = [d.isoformat() for d in days]

    rows = conn.execute("""
        SELECT substr(clicked_at, 1, 10) as day, COUNT(*) as count
        FROM clicks WHERE day >= ? GROUP BY day
    """, (day_strs[0],)).fetchall()
    counts_by_day = {d: c for d, c in rows}
    daily = [{"day": d[5:], "count": counts_by_day.get(d, 0)} for d in day_strs]

    peak_day = max(daily, key=lambda r: r["count"])["count"] if daily else 0
    avg_per_day = round(sum(r["count"] for r in daily) / len(daily)) if daily else 0

    referrer_rows = conn.execute("SELECT referrer FROM clicks").fetchall()
    ref_counts = defaultdict(int)
    for (ref,) in referrer_rows:
        ref_counts[_referrer_label(ref)] += 1
    top_referrers = sorted(ref_counts.items(), key=lambda kv: -kv[1])[:5]
    max_ref = max((c for _, c in top_referrers), default=1) or 1

    ua_rows = conn.execute("SELECT user_agent FROM clicks").fetchall()
    device_counts = defaultdict(int)
    for (ua,) in ua_rows:
        device_counts[_classify_device(ua)] += 1
    total_devices = sum(device_counts.values()) or 1
    device_breakdown = [
        {"name": name, "pct": round(device_counts.get(name, 0) * 100 / total_devices)}
        for name in ["Desktop", "Mobile", "Tablet"]
    ]

    conn.close()
    return {
        "total_clicks": total_clicks,
        "unique_links": unique_links,
        "peak_day": peak_day,
        "avg_per_day": avg_per_day,
        "daily": daily,
        "top_referrers": [{"name": n, "count": c, "pct": round(c * 100 / max_ref)} for n, c in top_referrers],
        "device_breakdown": device_breakdown,
    }


# ---------------------------------------------------------------------------
# Shared styling
# ---------------------------------------------------------------------------

BASE_STYLE = """
:root {
    --bg: #0a0d0c;
    --card: #121613;
    --border: #232823;
    --text: #f2f5f2;
    --muted: #7c8a82;
    --mint: #2ee6a8;
    --mint-dim: rgba(46, 230, 168, 0.12);
}
* { box-sizing: border-box; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    margin: 0;
}
.eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--mint);
}
.muted-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
}
nav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 40px;
    border-bottom: 1px solid var(--border);
}
.logo { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 17px; }
.logo-mark { width: 22px; height: 22px; background: var(--mint); border-radius: 5px; }
.nav-links { display: flex; gap: 28px; font-size: 14px; }
.nav-links a { color: var(--muted); text-decoration: none; }
.nav-links a.active { color: var(--mint); }
.nav-links a:hover { color: var(--text); }
main { max-width: 1080px; margin: 0 auto; padding: 40px; }
.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0 36px; }
@media (max-width: 800px) { .stat-grid { grid-template-columns: repeat(2, 1fr); } }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
.stat-num { font-family: 'JetBrains Mono', monospace; font-size: 28px; font-weight: 700; margin-top: 6px; }
.stat-num small { font-size: 13px; color: var(--muted); font-weight: 400; }
a { color: inherit; }
"""


# ---------------------------------------------------------------------------
# Routes: dashboard
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    stats = get_dashboard_stats()

    links_html = "".join(f"""
        <div class="link-row">
            <div>
                <div class="link-code">snip/{l['code']}</div>
                <div class="link-url">{l['url']}</div>
            </div>
            <div class="link-meta">
                <div class="link-clicks">{l['clicks']}<span>clicks</span></div>
                <div class="link-date">{l['created_at']}</div>
                <a class="link-btn" href="/stats/{l['code']}" target="_blank">Stats</a>
            </div>
        </div>
    """ for l in stats["recent_links"]) or "<div class='empty'>No links yet &mdash; shorten your first URL above.</div>"

    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Snip</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        {BASE_STYLE}
        .hero {{ margin-bottom: 8px; }}
        h1 {{ font-size: 46px; font-weight: 800; line-height: 1.08; margin: 10px 0 14px; letter-spacing: -0.01em; }}
        h1 .accent {{ color: var(--mint); }}
        .subtext {{ color: var(--muted); font-size: 15px; max-width: 480px; line-height: 1.6; }}
        .top-row {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 40px; flex-wrap: wrap; }}
        .top-stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; min-width: 320px; }}
        .top-stats .stat-card {{ padding: 16px 18px; }}

        .shorten-box {{
            background: var(--card); border: 1px solid var(--border); border-radius: 12px;
            padding: 28px; margin: 40px 0 44px; display: flex; gap: 14px; align-items: flex-end; flex-wrap: wrap;
        }}
        .shorten-field {{ flex: 1; min-width: 260px; }}
        input[type=text] {{
            width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
            padding: 13px 14px; color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 13px;
        }}
        input[type=text]:focus {{ outline: none; border-color: var(--mint); }}
        button {{
            background: var(--mint); color: #06120d; border: none; border-radius: 8px;
            padding: 13px 20px; font-weight: 700; font-size: 14px; cursor: pointer; white-space: nowrap;
        }}
        button:hover {{ filter: brightness(1.08); }}
        button:focus-visible {{ outline: 2px solid var(--mint); outline-offset: 2px; }}

        #result {{ margin-top: 18px; }}
        .stub {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; padding-top: 14px; border-top: 1px dashed var(--border); }}
        .stub.ok .tag {{ color: var(--mint); }}
        .stub.err .tag {{ color: #e6644a; }}
        .stub .tag {{ font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-size: 11px; }}
        .stub a {{ color: var(--mint); text-decoration: underline; }}
        .stub .meta {{ color: var(--muted); margin-top: 6px; font-size: 12px; }}

        .recent-head {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 14px; }}
        .link-row {{
            display: flex; justify-content: space-between; align-items: center; gap: 20px;
            padding: 16px 4px; border-bottom: 1px dashed var(--border); flex-wrap: wrap;
        }}
        .link-code {{ color: var(--mint); font-family: 'JetBrains Mono', monospace; font-weight: 600; font-size: 14px; }}
        .link-url {{ color: var(--muted); font-size: 12px; margin-top: 3px; word-break: break-all; }}
        .link-meta {{ display: flex; align-items: center; gap: 18px; }}
        .link-clicks {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 14px; text-align: right; }}
        .link-clicks span {{ display: block; font-weight: 400; font-size: 10px; color: var(--muted); text-transform: uppercase; }}
        .link-date {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); }}
        .link-btn {{ font-size: 12px; border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; text-decoration: none; color: var(--text); }}
        .link-btn:hover {{ border-color: var(--mint); color: var(--mint); }}
        .empty {{ color: var(--muted); font-size: 13px; padding: 20px 4px; }}
    </style>
</head>
<body>
    <nav>
        <div class="logo"><span class="logo-mark"></span> snip</div>
        <div class="nav-links">
            <a href="/" class="active">Dashboard</a>
            <a href="/analytics">Analytics</a>
        </div>
    </nav>
    <main>
        <div class="top-row">
            <div class="hero">
                <div class="eyebrow">SNIP</div>
                <h1>Long links,<br><span class="accent">cut short.</span></h1>
                <div class="subtext">Paste any URL and get a compact link instantly. Track every click in one dashboard.</div>
            </div>
            <div class="top-stats">
                <div class="stat-card"><div class="muted-eyebrow">Total Links</div><div class="stat-num">{stats['total_links']}</div></div>
                <div class="stat-card"><div class="muted-eyebrow">Total Clicks</div><div class="stat-num">{stats['total_clicks']}</div></div>
                <div class="stat-card"><div class="muted-eyebrow">This Week</div><div class="stat-num">{stats['this_week']}<small> new</small></div></div>
                <div class="stat-card"><div class="muted-eyebrow">Avg. Clicks</div><div class="stat-num">{stats['avg_clicks']}<small> /link</small></div></div>
            </div>
        </div>

        <div class="shorten-box">
            <div class="shorten-field">
                <div class="muted-eyebrow" style="margin-bottom:8px;">Paste your long URL</div>
                <input type="text" id="urlInput" placeholder="https://example.com/very/long/path/to/something">
                <div id="result"></div>
            </div>
            <button onclick="shortenUrl()">Shorten URL &rarr;</button>
        </div>

        <div class="recent-head">
            <div class="muted-eyebrow">Recent Links &mdash; {stats['total_links']}</div>
            <div class="muted-eyebrow">sorted by newest</div>
        </div>
        {links_html}
    </main>

    <script>
        async function shortenUrl() {{
            const url = document.getElementById('urlInput').value;
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = "";

            try {{
                const response = await fetch('/shorten', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ url: url }})
                }});
                const data = await response.json();

                if (response.ok) {{
                    resultDiv.className = "stub ok";
                    resultDiv.innerHTML =
                        '<div class="tag">Issued</div>' +
                        '<div><a href="' + data.short_url + '" target="_blank">' + data.short_url + '</a></div>' +
                        '<div class="meta"><a href="/stats/' + data.code + '" target="_blank">view stats &rarr;</a> &middot; refresh to see it in the list below</div>';
                }} else {{
                    resultDiv.className = "stub err";
                    resultDiv.innerHTML = '<div class="tag">Declined</div><div>' + data.error + '</div>';
                }}
            }} catch (err) {{
                resultDiv.className = "stub err";
                resultDiv.innerHTML = '<div class="tag">Error</div><div>' + err + '</div>';
            }}
        }}
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
    return jsonify({"code": code, "short_url": f"{request.host_url}{code}"}), 201


@app.route("/analytics", methods=["GET"])
def analytics_page():
    a = get_analytics_overview()
    day_labels = [d["day"] for d in a["daily"]]
    day_counts = [d["count"] for d in a["daily"]]

    referrer_rows = "".join(f"""
        <div class="ref-row">
            <div class="ref-name">{r['name']}</div>
            <div class="ref-bar-track"><div class="ref-bar" style="width:{r['pct']}%"></div></div>
            <div class="ref-count">{r['count']}</div>
        </div>
    """ for r in a["top_referrers"]) or "<div class='empty'>No click data yet</div>"

    device_rows = "".join(f"""
        <div class="dev-row">
            <div class="dev-head"><span>{d['name']}</span><span class="mint">{d['pct']}%</span></div>
            <div class="dev-track"><div class="dev-bar" style="width:{d['pct']}%"></div></div>
        </div>
    """ for d in a["device_breakdown"])

    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Snip &middot; Analytics</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        {BASE_STYLE}
        h1 {{ font-size: 34px; font-weight: 800; margin: 8px 0 6px; }}
        .subtext {{ color: var(--muted); font-size: 14px; margin-bottom: 30px; }}
        .chart-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 20px; }}
        .split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 800px) {{ .split {{ grid-template-columns: 1fr; }} }}
        .ref-row {{ display: grid; grid-template-columns: 70px 1fr 34px; align-items: center; gap: 12px; margin-bottom: 12px; font-size: 13px; }}
        .ref-bar-track {{ background: var(--bg); border-radius: 4px; height: 10px; overflow: hidden; }}
        .ref-bar {{ background: var(--mint); height: 100%; }}
        .ref-count {{ font-family: 'JetBrains Mono', monospace; text-align: right; color: var(--muted); }}
        .dev-row {{ margin-bottom: 18px; }}
        .dev-head {{ display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px; }}
        .dev-head .mint {{ color: var(--mint); font-family: 'JetBrains Mono', monospace; }}
        .dev-track {{ background: var(--bg); border-radius: 4px; height: 8px; overflow: hidden; }}
        .dev-bar {{ background: var(--mint); height: 100%; }}
    </style>
</head>
<body>
    <nav>
        <div class="logo"><span class="logo-mark"></span> snip</div>
        <div class="nav-links">
            <a href="/">Dashboard</a>
            <a href="/analytics" class="active">Analytics</a>
        </div>
    </nav>
    <main>
        <div class="eyebrow">ANALYTICS</div>
        <h1>Click Overview</h1>
        <div class="subtext">Last 7 days across all links</div>

        <div class="stat-grid">
            <div class="stat-card"><div class="muted-eyebrow">Total Clicks</div><div class="stat-num">{a['total_clicks']}</div></div>
            <div class="stat-card"><div class="muted-eyebrow">Unique Links</div><div class="stat-num">{a['unique_links']}</div></div>
            <div class="stat-card"><div class="muted-eyebrow">Peak Day</div><div class="stat-num">{a['peak_day']}</div></div>
            <div class="stat-card"><div class="muted-eyebrow">Avg / Day</div><div class="stat-num">{a['avg_per_day']}</div></div>
        </div>

        <div class="chart-card">
            <div class="muted-eyebrow" style="margin-bottom:16px;">Daily Clicks</div>
            <canvas id="dailyChart" height="90"></canvas>
        </div>

        <div class="split">
            <div class="chart-card">
                <div class="muted-eyebrow" style="margin-bottom:16px;">Top Referrers</div>
                {referrer_rows}
            </div>
            <div class="chart-card">
                <div class="muted-eyebrow" style="margin-bottom:16px;">Device Breakdown</div>
                {device_rows}
            </div>
        </div>
    </main>

    <script>
        const ctx = document.getElementById('dailyChart');
        const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 220);
        gradient.addColorStop(0, 'rgba(46, 230, 168, 0.35)');
        gradient.addColorStop(1, 'rgba(46, 230, 168, 0)');

        new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: {day_labels},
                datasets: [{{
                    data: {day_counts},
                    borderColor: '#2ee6a8',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    borderWidth: 2
                }}]
            }},
            options: {{
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    y: {{ beginAtZero: true, ticks: {{ color: '#7c8a82' }}, grid: {{ color: '#232823' }} }},
                    x: {{ ticks: {{ color: '#7c8a82' }}, grid: {{ display: false }} }}
                }}
            }}
        }});
    </script>
</body>
</html>
    """


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
        f"<tr><td>{r['clicked_at']}</td><td>{_referrer_label(r['referrer'])}</td><td>{(r['user_agent'] or '')[:60]}</td></tr>"
        for r in stats["recent"]
    ) or "<tr><td colspan='3'>No clicks yet</td></tr>"

    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Snip &middot; /{code}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        {BASE_STYLE}
        main {{ max-width: 700px; }}
        h1 {{ font-size: 26px; font-weight: 800; margin: 8px 0 4px; color: var(--mint); }}
        .original {{ font-size: 13px; color: var(--muted); margin-bottom: 26px; word-break: break-all; }}
        .chart-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
        th {{ text-align: left; padding: 8px; border-bottom: 1px solid var(--border); color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; }}
        td {{ padding: 8px; border-bottom: 1px dashed var(--border); }}
        tr:last-child td {{ border-bottom: none; }}
        .back {{ font-size: 12px; color: var(--muted); text-decoration: none; }}
        .back:hover {{ color: var(--mint); }}
    </style>
</head>
<body>
    <nav>
        <div class="logo"><span class="logo-mark"></span> snip</div>
        <div class="nav-links"><a href="/">Dashboard</a><a href="/analytics">Analytics</a></div>
    </nav>
    <main>
        <a class="back" href="/">&larr; back to dashboard</a>
        <div class="eyebrow" style="margin-top:16px;">LINK</div>
        <h1>/{code}</h1>
        <div class="original">redirects to <a href="{original_url}" target="_blank">{original_url}</a></div>

        <div class="stat-grid" style="grid-template-columns: 1fr;">
            <div class="stat-card"><div class="muted-eyebrow">Total Clicks</div><div class="stat-num">{stats['total']}</div></div>
        </div>

        <div class="chart-card">
            <div class="muted-eyebrow" style="margin-bottom:16px;">Clicks over time</div>
            <canvas id="clicksChart" height="90"></canvas>
        </div>

        <div class="chart-card">
            <div class="muted-eyebrow" style="margin-bottom:16px;">Recent activity</div>
            <table>
                <tr><th>When</th><th>Referrer</th><th>Browser / device</th></tr>
                {recent_rows}
            </table>
        </div>
    </main>

    <script>
        new Chart(document.getElementById('clicksChart'), {{
            type: 'bar',
            data: {{
                labels: {days_labels},
                datasets: [{{
                    data: {days_counts},
                    backgroundColor: '#2ee6a8',
                    borderRadius: 3,
                    maxBarThickness: 26
                }}]
            }},
            options: {{
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    y: {{ beginAtZero: true, ticks: {{ stepSize: 1, color: '#7c8a82' }}, grid: {{ color: '#232823' }} }},
                    x: {{ ticks: {{ color: '#7c8a82' }}, grid: {{ display: false }} }}
                }}
            }}
        }});
    </script>
</body>
</html>
    """


if __name__ == "__main__":
    app.run(debug=True, port=5000)