import re
import urllib.parse
import hashlib
import math
import requests
from dataclasses import dataclass, field
from typing import Optional


## Suspicious patterns

SUSPICIOUS_KEYWORDS = [
	"login", "signin", "verify", "account", "secure", "update", "banking", "paypal", "amazon", "apple",
	"google", "microsoft", "support", "confirm", "password", "credential", "wallet", "ebay", "netflix",
	"instagram", "facebook", "office365",
]

SUSPICIOUS_TLDS = [
	".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link", ".online", ".site",
	".info", ".biz", ".pw", ".cc",
]

LEGITIMATE_DOMAINS = {
	"google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com", "paypal.com", "netflix.com",
	"instagram.com", "twitter.com", "linkedin.com", "github.com", "youtube.com",
}

URL_SHORTENERS = {
	"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "shorte.st",
}


## Result dataclass

@dataclass
class DetectionResult:
	url: str
	score: float
	verdict: str
	flags: list[str] = field(default_factory=list)
	virustotal: Optional[dict] = None
	heuristic_breakdown: dict = field(default_factory=dict)

	@property
	def risk_percent(self) -> int:
	    return round(self.score * 100)

## Helpers

def entropy(s: str) -> float:
    """Shannon entropy - high values indicate random/obfuscated strings."""
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def extract_parts(url: str) -> dict:
    """ Parse a URL into its structural components."""
    if not url.startswith(("https://", "https://")):
       url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""


# Strip www.

    domain = re.sub(r"^www\.", "", hostname)

# Extract subdomain vs root domain 
    parts = domain.split(".")
    if len(parts) >= 2:
       root_domain = ".".join(parts[-2:])
       subdomains = parts[:-2]
    else:
       root_domain = domain
       subdomains = []

    return {
       "full_url": url,
       "scheme": parsed.scheme,
       "hostname": hostname,
       "domain": domain, 
       "root_domain": root_domain, 
       "subdomains": subdomains,
       "path": path, 
       "query": query, 
       "tld": "." + parts[-1] if parts else "",
}



## Heuristic checks


def check_https(p: dict) -> Optional[tuple]:
    if p["scheme"] != "https":
        return (0.15, "No HTTPS - connection is unenrypted")
    return None


def check_url_length(p: dict) -> Optional[tuple]:
    length = len(p["full_url"])
    if length > 100:
        return(0.10, f"Unusually long URL ({length} chars)")
    return None


def check_ip_address(p: dict) -> Optional[tuple]:
    if re.match(r"^\d{1.3}(\.\d{1,3}){3}$", p["hostname"]):
        return(0.30, "URL uses raw IP address instead of domain name")
    return None


def check_suspicious_tld(p: dict) -> Optional[tuple]:
    for tld in SUSPICIOUS_TLDS:
        if p["root_domain"].endswith(tld):
           return (0.20, f"High-risk TLD: {p['tld']}")
    return None



def check_subdomain_depth(p: dict) -> Optional[tuple]:
    depth = len(p["subdomains"])
    if depth >= 3:
        return (0.20, f"Excessive subdomain depth ({depth} levels)")
    elif depth == 2:
        return (0.20, f"Multiple subdomains ({depth} levels)")
    return None


def check_brand_in_subdomain(p: dict) -> Optional[tuple]:
    sub_str = ".".join(p["subdomains"]).lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in sub_str:
           for brand in ["paypal", "amazon", "apple", "microsoft", "google", "facebook"]:
               if brand in sub_str and brand not in p["root_domain"]:
                  return (0.35, f"Brand name '{brand}' in subdomain (possible spoofing)")
           return (0.15, f"Suspicious keyword '{keyword}' in subdomain")
    return None

def check_keywords_in_path(p: dict) -> Optional[tuple]:
    path_lower = p["path"].lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_lower]
    if len(hits) >= 3:
        return (0.25, f"Multiple phishing keywords in path: {'.'.join(hits[:3])}")
    elif hits:
        return (0.10, f"Phishing keyword in path: '{hits[0]}'")
    return None


def check_url_shortener(p: dict)-> Optional[tuple]:
    if p["root_domain"] in URL_SHORTENERS:
        return (0.20, f"URL shortener detected ({p['root_domain']}) - destination unknown")
    return None

def check_hex_encoding(p: dict) -> Optional[tuple]:
    if re.search(r"%[0-9a-fA-F]{2}", p["full_url"]):
        count = len(re.findall(r"%[0-9a-fA-F]{2}" , p["full_url"]))
        if count >= 3:
            return (0.20, f"Heavy URL uncoding ({count} encoded chars) - possible obfuscation")
    return None

def check_entropy(p: dict) -> Optional[tuple]:
    domain_entropy = entropy(p["domain"])
    if domain_entropy > 4.0:
        return (0.25, f"High domain entropy ({domain_entropy:.2f} - likely algorithmically generated)")
    return None


def check_double_slash(p: dict) -> Optional[tuple]:
    if "//" in p["path"]:
        return (0.15, "Double slash in path - possible redirect trick")
    return None

def check_legitimate_domain(p: dict) -> Optional[tuple]:
    """Bonus: known-good domain reduces score."""
    if p["root_domain"] in LEGITIMATE_DOMAINS and not p["subdomains"]:
        return (-0.30, None) # negative weight = trust boost
    return None

ALL_CHECKS = [
    check_https,
    check_url_length,
    check_ip_address,
    check_suspicious_tld,
    check_subdomain_depth,
    check_brand_in_subdomain,
    check_keywords_in_path,
    check_url_shortener,
    check_hex_encoding,
    check_entropy,
    check_double_slash,
    check_legitimate_domain,
]


## Virus Integration

def check_virustotal(url: str, api_key: str) -> dict:
    """ Submit URl to VirusTotal and return a summary dict. Uses the v3 API with URL ID(base64url of the URL)."""
    import base64

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        resp = requests.get(endpoint, headers=headers, timeout=10)
        # url not yet in VT database - submit it
        if resp.status_code == 404:
            post_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            if post_resp.status_code == 200:
                return {"status": "submitted", "message": "URL submitted to VirusTotal. Re-run in ~30s for results."}
            return {"status": "error", "message": "Could not submit URL to VirusTotal"}


        if resp_status_code == 401:
            return {"status": "error", "message": "Invalid VirusTotal API key"}

        if resp_status_code != 200:
            return {"status": "error", "message": f"VirusTotal returned HTTP {resp.status_code}"}

        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values())

        return {
        "status": "ok",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_engines": total,
        "detection_rate": f"{malicious}/{total}",
        "vt_verdict": "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if suspicious >= 2 else "CLEAN",)
}

    except requests.exceptions.Timeout:
        return {"status": "error", "message": "VirusTotal request timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "message": "Could not connect to VirusTotal"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


## Main analysis function


def analyze(url: str, vt_api_key: Optional[str] = None) -> DetectionResult:
    """ Analyze a URL for phishing indicators. Returns a DetectionResult wiht score, verdict, and detailed flags"""
    url = url.strip()
    parts = extract_parts(url)

    raw_score = 0.0
    flags = []
    breakdown = {}

    for check in ALL_CHECKS:
        result = check(parts)
        if result is not None:
            weight, flag = result
            raw_score +=  weight
            breakdown[check.__name__] = {"weight": weight, "flag": flag}

            if flag:
                flags.append(flag)


# clamp to [0.1]

    score = max(0.0, min(1.0, raw_score))

#verdict thresholds

    if score < 0.25:
        verdict = "SAFE"
    elif score < 0.55:
        verdict = "SUSPICIOUS"
    else:
        verdict = "PHISHING"


# virustotal check
    vt_result = None
    if vt_api_key:
        vt_result = check_virustotal(url, vt_api_key)
        if vt_result.get("status") == "ok" and vt_result.get("vt_verdict") == "MALICIOUS":
           score = min(1.0, score + 0.30)
           verdict = "PHISHING"
           flags.insert(0, f"VirusTotal: {vt_result['detection_rate']} engines flagged this URL")

    return DetectionResult(
        url=url,
        score=score,
        verdict=verdict,
        flags=flags,
        virustotal=vt_result,
        heuristic_breakdown=breakdown,
)




































































