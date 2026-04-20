"""HTTP client for audit requests — passive observation only."""
import requests
from urllib.parse import urlparse


def fetch(url: str, timeout: int = 15) -> dict:
    """
    Fetch a URL and return headers, cookies, status, and content.
    User-Agent identifies as security research tool.
    Passive only — no exploitation, no form submission.
    """
    session = requests.Session()
    session.headers["User-Agent"] = "BASTION/1.0 Security Research (passive)"
    session.max_redirects = 5

    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "set_cookie_headers": [],
        "html": "",
        "final_url": url,
        "https": url.startswith("https://"),
        "redirect_chain": [],
        "error": None,
    }

    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["final_url"] = resp.url
        result["https"] = resp.url.startswith("https://")

        # Collect all Set-Cookie headers (requests deduplicates by default,
        # so we use raw headers from the response history + final)
        cookies_seen = set()
        for r in list(resp.history) + [resp]:
            raw_headers = r.raw.headers
            for key, val in raw_headers.items():
                if key.lower() == "set-cookie" and val not in cookies_seen:
                    result["set_cookie_headers"].append(val)
                    cookies_seen.add(val)

        if "text/html" in resp.headers.get("Content-Type", ""):
            result["html"] = resp.text[:200_000]  # cap at 200KB

        result["redirect_chain"] = [r.url for r in resp.history]

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "Connection timed out"
    except requests.RequestException as e:
        result["error"] = str(e)

    return result
