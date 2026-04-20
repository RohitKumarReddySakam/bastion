"""Analyze Set-Cookie headers for security attribute compliance."""
import re


def parse_cookies(set_cookie_headers: list[str]) -> list[dict]:
    """Parse Set-Cookie header values into structured dicts."""
    cookies = []
    for header in set_cookie_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        name = name_val.split("=")[0].strip() if "=" in name_val else name_val
        attrs = {p.split("=")[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
                 for p in parts[1:]}
        cookies.append({"name": name, "raw": header, "attrs": attrs})
    return cookies


def analyze(set_cookie_headers: list[str]) -> dict:
    if not set_cookie_headers:
        return {"findings": [], "cookies": []}

    cookies = parse_cookies(set_cookie_headers)
    findings = []

    for cookie in cookies:
        name = cookie["name"]
        attrs = cookie["attrs"]

        # Secure flag
        if not attrs.get("secure"):
            findings.append({
                "cookie": name,
                "issue": "Missing Secure flag",
                "severity": "HIGH",
                "owasp": "A02:2021",
                "description": f"Cookie '{name}' lacks Secure flag — can be sent over HTTP.",
                "fix": "Add Secure attribute to prevent transmission over unencrypted connections.",
            })

        # HttpOnly flag
        if not attrs.get("httponly"):
            findings.append({
                "cookie": name,
                "issue": "Missing HttpOnly flag",
                "severity": "HIGH",
                "owasp": "A03:2021",
                "description": f"Cookie '{name}' lacks HttpOnly — accessible via JavaScript (XSS risk).",
                "fix": "Add HttpOnly attribute to prevent JavaScript access.",
            })

        # SameSite
        samesite = str(attrs.get("samesite", "")).lower()
        if not samesite:
            findings.append({
                "cookie": name,
                "issue": "Missing SameSite attribute",
                "severity": "MEDIUM",
                "owasp": "A01:2021",
                "description": f"Cookie '{name}' lacks SameSite — vulnerable to CSRF.",
                "fix": "Add SameSite=Strict or SameSite=Lax.",
            })
        elif samesite == "none" and not attrs.get("secure"):
            findings.append({
                "cookie": name,
                "issue": "SameSite=None without Secure",
                "severity": "HIGH",
                "owasp": "A02:2021",
                "description": f"Cookie '{name}' uses SameSite=None without Secure flag.",
                "fix": "Add Secure flag when using SameSite=None.",
            })

        # Expiry check: no Expires/Max-Age = session cookie (acceptable)
        # If session-looking name without session scope, flag it
        session_names = {"sessionid", "session", "sid", "phpsessid", "asp.net_sessionid",
                          "jsessionid", "connect.sid"}
        if name.lower() in session_names:
            if attrs.get("max-age") or attrs.get("expires"):
                findings.append({
                    "cookie": name,
                    "issue": "Session Cookie with Persistent Expiry",
                    "severity": "MEDIUM",
                    "owasp": "A07:2021",
                    "description": f"Session cookie '{name}' has persistent expiry — session may not expire.",
                    "fix": "Use session cookies (no Expires/Max-Age) for authentication cookies.",
                })

    return {"findings": findings, "cookies": [c["name"] for c in cookies]}
