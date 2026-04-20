"""Map audit findings to OWASP Top 10 2021 categories."""

OWASP_TOP_10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

OWASP_RISK_PRIORITY = list(OWASP_TOP_10.keys())


def categorize(findings: list[dict]) -> dict:
    """Group findings by OWASP Top 10 category."""
    categories = {}
    uncategorized = []

    for finding in findings:
        owasp = finding.get("owasp", "")
        if owasp and owasp in OWASP_TOP_10:
            if owasp not in categories:
                categories[owasp] = {
                    "id": owasp,
                    "name": OWASP_TOP_10[owasp],
                    "findings": [],
                    "max_severity": "INFO",
                }
            categories[owasp]["findings"].append(finding)
            categories[owasp]["max_severity"] = _max_severity(
                categories[owasp]["max_severity"],
                finding.get("severity", "INFO")
            )
        else:
            uncategorized.append(finding)

    # Sort by OWASP priority order
    ordered = [categories[k] for k in OWASP_RISK_PRIORITY if k in categories]

    return {
        "categories": ordered,
        "uncategorized": uncategorized,
        "covered_categories": len(categories),
        "total_categories": len(OWASP_TOP_10),
    }


def overall_owasp_score(findings: list[dict]) -> dict:
    """
    Compute an overall OWASP compliance posture.
    Returns score 0-100 (higher = more secure) and letter grade.
    """
    severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    deduction = sum(severity_weights.get(f.get("severity", "INFO"), 0) for f in findings)
    score = max(0, 100 - deduction)
    grade = _score_to_grade(score)
    return {"score": score, "grade": grade}


def _max_severity(current: str, new: str) -> str:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return new if order.index(new) > order.index(current) else current


def _score_to_grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"
