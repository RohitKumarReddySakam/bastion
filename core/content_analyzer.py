"""Analyze HTML page content for security issues."""
import re

_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r'<script(?![^>]*src)[^>]*>(.*?)</script>',
                                 re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r'<input([^>]*)>', re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w[\w-]*)=["\']([^"\']*)["\']', re.IGNORECASE)
_LINK_RE = re.compile(r'href=["\']http://[^"\']+["\']', re.IGNORECASE)

SENSITIVE_COMMENT_PATTERNS = [
    (r"password\s*[:=]", "Hardcoded password in HTML comment"),
    (r"api[_\s]?key\s*[:=]", "API key in HTML comment"),
    (r"secret\s*[:=]", "Secret value in HTML comment"),
    (r"todo|fixme|hack", "Developer note in HTML comment"),
    (r"internal|staging|debug", "Internal note in HTML comment"),
]

DANGEROUS_JS_PATTERNS = [
    (r"document\.write\(", "Unsafe document.write() usage"),
    (r"eval\s*\(", "Dangerous eval() usage"),
    (r"innerHTML\s*=\s*[^;'\"]+\+", "Potential DOM XSS via innerHTML concatenation"),
]


def analyze(html: str, page_url: str = "") -> dict:
    findings = []

    # HTML comments
    for comment in _COMMENT_RE.findall(html):
        for pattern, desc in SENSITIVE_COMMENT_PATTERNS:
            if re.search(pattern, comment, re.IGNORECASE):
                findings.append({
                    "category": "Information Disclosure",
                    "issue": desc,
                    "severity": "MEDIUM",
                    "owasp": "A05:2021",
                    "description": f"Potentially sensitive information found in HTML comment.",
                    "fix": "Remove developer comments and sensitive data from production HTML.",
                })
                break

    # External scripts over HTTP
    for src in _SCRIPT_SRC_RE.findall(html):
        if src.startswith("http://"):
            findings.append({
                "category": "Mixed Content",
                "issue": f"Script loaded over HTTP: {src[:80]}",
                "severity": "HIGH",
                "owasp": "A02:2021",
                "description": "Script loaded over unencrypted HTTP allows MITM injection.",
                "fix": "Load all resources over HTTPS.",
            })

    # Inline JS dangerous patterns
    for script_body in _INLINE_SCRIPT_RE.findall(html):
        for pattern, desc in DANGEROUS_JS_PATTERNS:
            if re.search(pattern, script_body, re.IGNORECASE):
                findings.append({
                    "category": "Client-Side Injection",
                    "issue": desc,
                    "severity": "MEDIUM",
                    "owasp": "A03:2021",
                    "description": f"Dangerous JavaScript pattern detected: {desc}",
                    "fix": "Use safe DOM APIs (textContent, setAttribute) instead of eval/innerHTML/document.write.",
                })

    # Links over HTTP (mixed content)
    http_links = _LINK_RE.findall(html)
    if http_links:
        findings.append({
            "category": "Mixed Content",
            "issue": f"{len(http_links)} HTTP link(s) on HTTPS page",
            "severity": "LOW",
            "owasp": "A02:2021",
            "description": "Links pointing to HTTP URLs may cause mixed content warnings.",
            "fix": "Update all links to use HTTPS.",
        })

    # Autocomplete on password inputs
    for input_raw in _INPUT_RE.findall(html):
        attrs = dict(_ATTR_RE.findall(input_raw))
        if attrs.get("type", "").lower() == "password":
            ac = attrs.get("autocomplete", "").lower()
            if ac not in ("off", "new-password", "current-password"):
                findings.append({
                    "category": "Authentication",
                    "issue": "Password input allows browser autocomplete",
                    "severity": "LOW",
                    "owasp": "A07:2021",
                    "description": "Password field lacks autocomplete=off.",
                    "fix": 'Add autocomplete="new-password" or autocomplete="off" to password inputs.',
                })

    return {"findings": findings}
