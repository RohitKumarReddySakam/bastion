"""Analyze HTTP security headers against OWASP best practices."""

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "owasp": "A02:2021", "category": "Transport Security",
        "severity": "HIGH", "score_impact": 15,
        "description": "HSTS forces HTTPS connections. Missing allows downgrade attacks.",
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "owasp": "A03:2021", "category": "Injection",
        "severity": "HIGH", "score_impact": 15,
        "description": "CSP prevents XSS by restricting script sources.",
        "fix": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Content-Type-Options": {
        "owasp": "A05:2021", "category": "Misconfiguration",
        "severity": "MEDIUM", "score_impact": 5,
        "description": "Prevents MIME-type sniffing attacks.",
        "fix": "X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "owasp": "A04:2021", "category": "Insecure Design",
        "severity": "MEDIUM", "score_impact": 5,
        "description": "Prevents clickjacking by controlling framing.",
        "fix": "X-Frame-Options: DENY",
    },
    "Referrer-Policy": {
        "owasp": "A05:2021", "category": "Misconfiguration",
        "severity": "LOW", "score_impact": 3,
        "description": "Controls referrer header information leakage.",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "owasp": "A05:2021", "category": "Misconfiguration",
        "severity": "LOW", "score_impact": 2,
        "description": "Restricts browser feature access.",
        "fix": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

INFORMATION_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                                    "X-Generator", "X-Runtime"]

CSP_UNSAFE_DIRECTIVES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]


def analyze(headers: dict) -> dict:
    """
    Returns security grade, score, and per-header findings.
    Score starts at 100 and deductions applied for issues.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}
    findings = []
    score = 100

    # Check required security headers
    for header, meta in SECURITY_HEADERS.items():
        present = header.lower() in headers_lower
        if not present:
            score -= meta["score_impact"]
            findings.append({
                "header": header,
                "status": "missing",
                "severity": meta["severity"],
                "owasp": meta["owasp"],
                "category": meta["category"],
                "description": meta["description"],
                "fix": meta["fix"],
            })
        else:
            value = headers_lower[header.lower()]
            # Validate CSP for unsafe directives
            if header == "Content-Security-Policy":
                for unsafe in CSP_UNSAFE_DIRECTIVES:
                    if unsafe in value.lower():
                        score -= 5
                        findings.append({
                            "header": header,
                            "status": "weak",
                            "severity": "MEDIUM",
                            "owasp": "A03:2021",
                            "category": "Injection",
                            "description": f"CSP contains unsafe directive: {unsafe}",
                            "fix": f"Remove '{unsafe}' from CSP directives.",
                        })
            # Validate HSTS max-age
            elif header == "Strict-Transport-Security":
                if "max-age=" in value.lower():
                    try:
                        age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
                        if age < 31536000:
                            score -= 3
                            findings.append({
                                "header": header,
                                "status": "weak",
                                "severity": "LOW",
                                "owasp": "A02:2021",
                                "category": "Transport Security",
                                "description": f"HSTS max-age {age}s is less than 1 year (31536000s).",
                                "fix": "Set max-age=31536000 or higher.",
                            })
                    except ValueError:
                        pass

    # Information disclosure
    for header in INFORMATION_DISCLOSURE_HEADERS:
        if header.lower() in headers_lower:
            score -= 2
            findings.append({
                "header": header,
                "status": "exposed",
                "severity": "LOW",
                "owasp": "A05:2021",
                "category": "Misconfiguration",
                "description": f"{header}: {headers_lower[header.lower()]} — reveals technology stack.",
                "fix": f"Remove or suppress the {header} response header.",
            })

    # CORS wildcard
    if "access-control-allow-origin" in headers_lower:
        if headers_lower["access-control-allow-origin"] == "*":
            score -= 10
            findings.append({
                "header": "Access-Control-Allow-Origin",
                "status": "misconfigured",
                "severity": "MEDIUM",
                "owasp": "A01:2021",
                "category": "Broken Access Control",
                "description": "Wildcard CORS allows any origin cross-origin access.",
                "fix": "Restrict to specific trusted domains.",
            })

    score = max(0, score)
    grade = _score_to_grade(score)
    return {"score": score, "grade": grade, "findings": findings}


def _score_to_grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"
