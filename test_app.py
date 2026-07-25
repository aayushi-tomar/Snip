"""
Test suite for the URL shortener.
Run with: pytest test_app.py -v

Uses a temporary SQLite file per test session and mocks the Safe Browsing
API call so tests don't depend on a live network connection or API key.
"""

import os
import sqlite3
import pytest
from unittest.mock import patch

import app as app_module


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Use a fresh temporary database for every test, and reset the safety cache."""
    db_path = tmp_path / "test_urls.db"
    monkeypatch.setattr(app_module, "DB_FILE", str(db_path))
    app_module.init_db()
    app_module._safety_cache.clear()
    yield
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


# ---- Core logic tests ----

def test_generate_code_length():
    code = app_module.generate_code(8)
    assert len(code) == 8


def test_generate_code_is_random():
    codes = {app_module.generate_code() for _ in range(20)}
    assert len(codes) > 1  # extremely unlikely to collide 20 times if truly random


def test_is_valid_url_accepts_http_https():
    assert app_module.is_valid_url("https://example.com/page")
    assert app_module.is_valid_url("http://example.com/page")


def test_is_valid_url_rejects_bad_input():
    assert not app_module.is_valid_url("not-a-url")
    assert not app_module.is_valid_url("")
    assert not app_module.is_valid_url(None)


# ---- shorten() / resolve() with safety check mocked as "safe" ----

@patch("app.check_safe_browsing_api", return_value=True)
def test_shorten_and_resolve_roundtrip(mock_safe):
    code = app_module.shorten("https://example.com/hello")
    assert app_module.resolve(code) == "https://example.com/hello"


@patch("app.check_safe_browsing_api", return_value=True)
def test_shorten_rejects_invalid_url(mock_safe):
    with pytest.raises(ValueError):
        app_module.shorten("not-a-real-url")


def test_resolve_unknown_code_returns_none():
    assert app_module.resolve("doesnotexist") is None


@patch("app.generate_code")
@patch("app.check_safe_browsing_api", return_value=True)
def test_collision_retries_until_unique_code(mock_safe, mock_gen):
    # First call returns a code, second call (after "collision") returns a different one.
    mock_gen.side_effect = ["AAAAAA", "AAAAAA", "BBBBBB"]
    code1 = app_module.shorten("https://example.com/one")
    code2 = app_module.shorten("https://example.com/two")
    assert code1 == "AAAAAA"
    assert code2 == "BBBBBB"  # had to retry past the duplicate


# ---- Safety check behavior ----

@patch("app.check_safe_browsing_api", return_value=False)
def test_shorten_rejects_unsafe_url(mock_safe):
    with pytest.raises(ValueError):
        app_module.shorten("https://malicious-example.com/bad")


@patch("app.check_safe_browsing_api", side_effect=RuntimeError("API key missing"))
def test_safety_check_fails_closed_on_api_error(mock_safe):
    """
    Documents the chosen fallback behavior: if the Safe Browsing API call
    itself fails (network error, bad key, etc), we treat the URL as unsafe
    and reject it (fail closed), rather than letting it through unchecked.
    """
    with pytest.raises(ValueError):
        app_module.shorten("https://example.com/should-be-blocked-on-api-failure")


@patch("app.check_safe_browsing_api", return_value=True)
def test_safety_check_result_is_cached(mock_safe):
    app_module.is_safe_url("https://example.com/cached")
    app_module.is_safe_url("https://example.com/cached")
    # The underlying API check should only be called once due to caching.
    assert mock_safe.call_count == 1


# ---- Flask endpoint tests ----

@patch("app.check_safe_browsing_api", return_value=True)
def test_shorten_endpoint_success(mock_safe, client):
    response = client.post("/shorten", json={"url": "https://example.com/api-test"})
    assert response.status_code == 201
    assert "code" in response.get_json()


def test_shorten_endpoint_missing_url(client):
    response = client.post("/shorten", json={})
    assert response.status_code == 400


@patch("app.check_safe_browsing_api", return_value=False)
def test_shorten_endpoint_unsafe_url(mock_safe, client):
    response = client.post("/shorten", json={"url": "https://malicious-example.com/bad"})
    assert response.status_code == 400


def test_resolve_endpoint_not_found(client):
    response = client.get("/doesnotexist")
    assert response.status_code == 404


# ---- Analytics tests ----

@patch("app.check_safe_browsing_api", return_value=True)
def test_click_is_logged_on_resolve(mock_safe, client):
    response = client.post("/shorten", json={"url": "https://example.com/analytics-test"})
    code = response.get_json()["code"]

    client.get(f"/{code}", headers={"Referer": "https://google.com"})

    stats = app_module.get_click_stats(code)
    assert stats["total"] == 1
    assert stats["recent"][0]["referrer"] == "https://google.com"


@patch("app.check_safe_browsing_api", return_value=True)
def test_stats_endpoint_returns_page_for_valid_code(mock_safe, client):
    response = client.post("/shorten", json={"url": "https://example.com/stats-test"})
    code = response.get_json()["code"]

    stats_response = client.get(f"/stats/{code}")
    assert stats_response.status_code == 200
    assert code.encode() in stats_response.data


def test_stats_endpoint_404s_for_unknown_code(client):
    response = client.get("/stats/doesnotexist")
    assert response.status_code == 404


@patch("app.check_safe_browsing_api", return_value=True)
def test_multiple_clicks_increment_total(mock_safe, client):
    response = client.post("/shorten", json={"url": "https://example.com/multi-click"})
    code = response.get_json()["code"]

    client.get(f"/{code}")
    client.get(f"/{code}")
    client.get(f"/{code}")

    stats = app_module.get_click_stats(code)
    assert stats["total"] == 3