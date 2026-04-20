"""Tests for BASTION core analyzers and OWASP checker."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.header_analyzer import analyze as analyze_headers
from core.cookie_analyzer import analyze as analyze_cookies, parse_cookies
from core.content_analyzer import analyze as analyze_content
from core.owasp_checker import categorize, overall_owasp_score, _score_to_grade


# ─── Header Analyzer ──────────────────────────────────────────────

def test_empty_headers_max_deductions():
    result = analyze_headers({})
    assert result["score"] < 60
    assert result["grade"] in ("D", "F")
    assert len(result["findings"]) >= 5


def test_full_security_headers_high_score():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    result = analyze_headers(headers)
    assert result["score"] >= 90
    assert result["grade"] in ("A+", "A")


def test_csp_unsafe_inline_flagged():
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
    }
    result = analyze_headers(headers)
    checks = [f.get("issue", "") for f in result["findings"]]
    assert any("unsafe" in c.lower() for c in checks)


def test_hsts_short_max_age_flagged():
    headers = {
        "Strict-Transport-Security": "max-age=3600",
    }
    result = analyze_headers(headers)
    checks = [f.get("issue", "") for f in result["findings"]]
    assert any("hsts" in c.lower() or "max-age" in c.lower() for c in checks)


def test_server_header_exposed_flagged():
    headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
    result = analyze_headers(headers)
    checks = [f.get("issue", "") for f in result["findings"]]
    assert any("server" in c.lower() for c in checks)


def test_wildcard_cors_flagged():
    headers = {"Access-Control-Allow-Origin": "*"}
    result = analyze_headers(headers)
    checks = [f.get("issue", "") for f in result["findings"]]
    assert any("cors" in c.lower() for c in checks)


# ─── Cookie Analyzer ──────────────────────────────────────────────

def test_parse_cookie_basic():
    cookies = parse_cookies(["sessionid=abc123; Secure; HttpOnly; SameSite=Strict"])
    assert len(cookies) == 1
    assert cookies[0]["name"] == "sessionid"
    assert cookies[0]["attrs"].get("secure")
    assert cookies[0]["attrs"].get("httponly")


def test_cookie_missing_secure_flagged():
    result = analyze_cookies(["auth=token123; HttpOnly; SameSite=Strict"])
    issues = [f["issue"] for f in result["findings"]]
    assert any("Secure" in i for i in issues)


def test_cookie_missing_httponly_flagged():
    result = analyze_cookies(["auth=token123; Secure; SameSite=Strict"])
    issues = [f["issue"] for f in result["findings"]]
    assert any("HttpOnly" in i for i in issues)


def test_cookie_missing_samesite_flagged():
    result = analyze_cookies(["auth=token123; Secure; HttpOnly"])
    issues = [f["issue"] for f in result["findings"]]
    assert any("SameSite" in i for i in issues)


def test_secure_cookie_no_findings():
    result = analyze_cookies(["auth=token123; Secure; HttpOnly; SameSite=Strict"])
    assert len(result["findings"]) == 0


def test_no_cookies_no_findings():
    result = analyze_cookies([])
    assert len(result["findings"]) == 0


# ─── Content Analyzer ─────────────────────────────────────────────

def test_http_script_src_flagged():
    html = '<script src="http://evil.com/bad.js"></script>'
    result = analyze_content(html)
    issues = [f["issue"] for f in result["findings"]]
    assert any("http" in i.lower() for i in issues)


def test_eval_in_script_flagged():
    html = '<script>eval(userInput)</script>'
    result = analyze_content(html)
    issues = [f["issue"] for f in result["findings"]]
    assert any("eval" in i.lower() for i in issues)


def test_sensitive_comment_flagged():
    html = '<!-- password: admin123 -->'
    result = analyze_content(html)
    issues = [f["issue"] for f in result["findings"]]
    assert any("password" in i.lower() for i in issues)


def test_clean_html_no_findings():
    html = '<html><head></head><body><h1>Hello</h1></body></html>'
    result = analyze_content(html)
    assert len(result["findings"]) == 0


# ─── OWASP Checker ────────────────────────────────────────────────

def test_categorize_maps_findings():
    findings = [
        {"owasp": "A02:2021", "severity": "HIGH", "issue": "No HTTPS"},
        {"owasp": "A03:2021", "severity": "HIGH", "issue": "CSP missing"},
        {"owasp": "A02:2021", "severity": "MEDIUM", "issue": "Weak cipher"},
    ]
    result = categorize(findings)
    assert result["covered_categories"] == 2
    cat_ids = [c["id"] for c in result["categories"]]
    assert "A02:2021" in cat_ids
    assert "A03:2021" in cat_ids


def test_overall_score_no_findings():
    result = overall_owasp_score([])
    assert result["score"] == 100
    assert result["grade"] == "A+"


def test_overall_score_critical_findings():
    findings = [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}, {"severity": "HIGH"}]
    result = overall_owasp_score(findings)
    assert result["score"] < 50
    assert result["grade"] in ("D", "F")


def test_grade_mapping():
    assert _score_to_grade(100) == "A+"
    assert _score_to_grade(90) == "A"
    assert _score_to_grade(75) == "B"
    assert _score_to_grade(60) == "C"
    assert _score_to_grade(50) == "D"
    assert _score_to_grade(30) == "F"
