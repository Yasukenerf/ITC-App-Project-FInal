"""Core phishing analysis logic (UI-agnostic).

This module powers the "Phishing Email Detector" project.

Design goals (assessment-friendly):
- Explainable results (points + reasons) for demo + report.
- Heuristic-based detection (fast, transparent) with reduced false positives.
- Web-friendly (DAST tools like OWASP ZAP require HTTP endpoints).

NOTE: This is not a full email security gateway. It is an educational detector.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from urllib.parse import urlparse


@dataclass
class AnalysisResult:
    score: int
    level: str
    keywords: List[str]
    urls: List[Dict[str, Any]]
    sensitive: List[str]
    header_issues: List[str]
    attachment_issues: List[str]
    breakdown: List[Dict[str, Any]]  # [{"points": 15, "category": "URL", "reason": "..."}, ...]


class PhishingAnalyzer:
    """Explainable phishing analyzer.

    Inputs:
      - `email_text`: may be plain text or a raw email with headers.

    Output:
      - score (0-100), level (Low/Medium/High), and evidence lists.
    """

    # Domain allowlist (reduces false positives; safe default set)
    TRUSTED_DOMAINS = {
        "microsoft.com",
        "office.com",
        "outlook.com",
        "google.com",
        "gmail.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "australia.gov.au",
        "my.gov.au",
        "ato.gov.au",
        "cihe.edu.au",
    }

    SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "goo.gl",
    }

    SUSPICIOUS_TOKENS = {
        "login",
        "verify",
        "secure",
        "update",
        "confirm",
        "account",
        "signin",
        "password",
        "billing",
        "payment",
    }

    RISKY_EXTENSIONS = {
        "exe",
        "js",
        "vbs",
        "scr",
        "bat",
        "cmd",
        "ps1",
        "iso",
        "img",
        "zip",
        "rar",
        "7z",
        "docm",
        "xlsm",
        "pptm",
    }

    def __init__(self, keyword_file: str | None = None):
        if keyword_file is None:
            keyword_file = os.path.join(os.path.dirname(__file__), "phishing_keywords.txt")
        self.keyword_file = keyword_file
        self.keywords = self._load_keywords(keyword_file)

    @staticmethod
    def _load_keywords(path: str) -> List[str]:
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]

    # --------------------------- public API ---------------------------

    def analyze(self, email_text: str) -> AnalysisResult:
        email_text = (email_text or "").strip()
        if not email_text:
            return AnalysisResult(
                score=0,
                level="Low Risk",
                keywords=[],
                urls=[],
                sensitive=[],
                header_issues=[],
                attachment_issues=[],
                breakdown=[],
            )

        breakdown: List[Dict[str, Any]] = []

        keyword_matches = self.find_keywords(email_text, self.keywords)
        suspicious_urls = self.find_suspicious_urls(email_text, breakdown)
        sensitive_info = self.detect_sensitive_requests(email_text, breakdown)
        header_issues = self.detect_header_issues(email_text, breakdown)
        attachment_issues = self.detect_attachment_issues(email_text, breakdown)

        score = self.calculate_risk_score(
            keyword_matches=keyword_matches,
            urls=suspicious_urls,
            sensitive=sensitive_info,
            header_issues=header_issues,
            attachment_issues=attachment_issues,
            breakdown=breakdown,
        )
        level = self.get_risk_level(score)

        return AnalysisResult(
            score=score,
            level=level,
            keywords=sorted(keyword_matches),
            urls=suspicious_urls,
            sensitive=sensitive_info,
            header_issues=header_issues,
            attachment_issues=attachment_issues,
            breakdown=breakdown,
        )

    # --------------------------- keyword checks ---------------------------

    @staticmethod
    def find_keywords(text: str, keywords: List[str]) -> List[str]:
        found: List[str] = []
        t = text.lower()
        for kw in keywords:
            if kw and kw in t:
                found.append(kw)
        # Deduplicate
        return sorted(list(set(found)))

    # --------------------------- URL checks ---------------------------

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """Extract URLs *and* common obfuscated domains.

        The app is used in a security class, so test emails often contain
        indicators like `example[.]com` to avoid making a clickable link.
        We treat those as URL-like signals too.
        """

        # Standard http(s) URLs
        url_pattern = r"https?://[^\s\]\)\>\"']+"
        urls = set(re.findall(url_pattern, text))

        # Obfuscated domains like secure-login[.]example.com/path
        # (avoid matching emails like name@example.com by requiring a dot TLD)
        obfus_pattern = r"\b(?:[A-Za-z0-9-]+(?:\[\.\]|\.)?)+\[\.\](?:[A-Za-z]{2,})(?:/[^\s\]\)\>\"']*)?\b"
        for m in re.findall(obfus_pattern, text):
            urls.add(m)

        return sorted(urls)

    @classmethod
    def _domain_matches_trusted(cls, host: str) -> bool:
        host = (host or "").lower().strip(".")
        if not host:
            return False
        if host in cls.TRUSTED_DOMAINS:
            return True
        # subdomain of trusted domain
        return any(host.endswith("." + d) for d in cls.TRUSTED_DOMAINS)

    @staticmethod
    def _is_ipv4(host: str) -> bool:
        return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or ""))

    @classmethod
    def _url_signals(cls, url: str) -> Tuple[List[str], int]:
        """Return (issues, points) for a URL."""
        issues: List[str] = []
        points = 0

        original = url
        # Normalize common obfuscation.
        url = (url or "").replace("[.]", ".").replace("(.)", ".").strip()
        if url != original:
            issues.append("Obfuscated domain format detected")
            points += 10

        # urlparse can behave oddly if there is no scheme.
        # For analysis, assume https when scheme is missing.
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url_for_parse = "https://" + url
        else:
            url_for_parse = url

        # urlparse may raise ValueError for malformed bracketed IPv6 hosts
        # (common in test phishing emails, e.g. obfuscated/broken links).
        try:
            parsed = urlparse(url_for_parse)
        except ValueError:
            issues.append("Malformed URL detected (invalid host syntax)")
            points += 20
            return issues, points
        scheme = (parsed.scheme or "").lower()
        netloc = parsed.netloc or ""
        host = netloc

        # userinfo@host handling
        if "@" in netloc:
            issues.append("URL contains '@' (possible userinfo/redirect trick)")
            points += 18
            host = netloc.split("@", 1)[-1]

        host = host.split(":", 1)[0].lower().strip(".")

        if scheme == "http":
            issues.append("Non-secure HTTP connection")
            points += 10

        if cls._is_ipv4(host):
            issues.append("IP address used as domain (common in phishing)")
            points += 22

        if "xn--" in host:
            issues.append("Punycode domain detected (possible lookalike/IDN spoofing)")
            points += 18

        # Many subdomains can indicate impersonation
        if host.count(".") >= 3:
            issues.append("Excessive subdomains (possible brand impersonation)")
            points += 10

        # Shortener domains
        if host in cls.SHORTENERS:
            issues.append("URL shortener detected")
            points += 16

        # Suspicious tokens in host/path/query
        path_q = (parsed.path or "") + " " + (parsed.query or "")
        combined = f"{host} {path_q}".lower()
        token_hits = [tok for tok in cls.SUSPICIOUS_TOKENS if tok in combined]
        if token_hits:
            issues.append(f"Suspicious tokens present: {', '.join(sorted(token_hits))}")
            points += min(18, 6 + 2 * len(token_hits))

        # Trusted domain reduces points slightly (but never below 0)
        if cls._domain_matches_trusted(host) and points > 0:
            issues.append("Trusted domain observed (reduces likelihood)")
            points = max(points - 8, 0)

        return issues, points

    @classmethod
    def find_suspicious_urls(cls, text: str, breakdown: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        urls = cls._extract_urls(text)
        suspicious: List[Dict[str, Any]] = []

        for url in urls:
            issues, points = cls._url_signals(url)
            # Only record URLs that have any issues worth showing
            if issues:
                suspicious.append({"url": url, "issues": issues, "points": points})
                if breakdown is not None and points > 0:
                    breakdown.append({"points": points, "category": "URL", "reason": f"{url} → {issues[0]}"})

        return suspicious

    # --------------------------- sensitive request checks ---------------------------

    @staticmethod
    def _add_breakdown(breakdown: Optional[List[Dict[str, Any]]], points: int, category: str, reason: str):
        if breakdown is None or points <= 0:
            return
        breakdown.append({"points": points, "category": category, "reason": reason})

    @classmethod
    def detect_sensitive_requests(cls, text: str, breakdown: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        t = text.lower()
        requests: List[str] = []

        if re.search(r"\b(password|passwd|pwd|one[- ]time\s*code|otp)\b", t):
            requests.append("Password/OTP requested")
            cls._add_breakdown(breakdown, 28, "Sensitive", "Requests password/OTP")

        if re.search(r"(credit\s*card|card\s*number|cvv|cvc|ssn|social\s*security)", t):
            requests.append("Credit card / SSN requested")
            cls._add_breakdown(breakdown, 32, "Sensitive", "Requests credit card/SSN")

        if re.search(r"(confirm.*identity|verify.*account|validate.*info|re-?enter.*password)", t):
            requests.append("Identity or credential verification requested")
            cls._add_breakdown(breakdown, 18, "Sensitive", "Forces identity/credential verification")

        if re.search(r"(banking|account|payment)\s*(information|details|credentials)", t):
            requests.append("Banking/payment details requested")
            cls._add_breakdown(breakdown, 22, "Sensitive", "Requests banking/payment details")

        return requests

    # --------------------------- header checks ---------------------------

    @staticmethod
    def _extract_domain_from_addr(addr: str) -> str:
        # very small parser: take anything after '@'
        m = re.search(r"@([A-Za-z0-9.-]+)", addr or "")
        return (m.group(1) if m else "").lower().strip(".")

    @classmethod
    def detect_header_issues(cls, text: str, breakdown: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        issues: List[str] = []

        # Basic From/Reply-To checks
        from_m = re.search(r"^From:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        reply_m = re.search(r"^Reply-To:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        auth_m = re.search(r"^Authentication-Results:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)

        from_val = from_m.group(1).strip() if from_m else ""
        reply_val = reply_m.group(1).strip() if reply_m else ""

        from_dom = cls._extract_domain_from_addr(from_val)
        reply_dom = cls._extract_domain_from_addr(reply_val)

        if from_dom and reply_dom and from_dom != reply_dom:
            issues.append("Reply-To domain differs from From domain (possible spoofing)")
            cls._add_breakdown(breakdown, 18, "Header", f"From domain '{from_dom}' vs Reply-To '{reply_dom}'")

        # Authentication-Results (if present)
        # Many raw emails include spf/dkim/dmarc result tokens.
        auth_line = auth_m.group(1) if auth_m else ""
        auth_blob = (auth_line + "\n" + text).lower()
        for token, pts, label in [
            ("spf=fail", 18, "SPF fail"),
            ("dkim=fail", 18, "DKIM fail"),
            ("dmarc=fail", 18, "DMARC fail"),
        ]:
            if token in auth_blob:
                issues.append(f"Authentication-Results indicates {label}")
                cls._add_breakdown(breakdown, pts, "Header", f"{label} detected")

        # Display name spoofing (very basic): brand-like word with free email domain
        if from_val and from_dom and any(free in from_dom for free in ["gmail.com", "outlook.com", "yahoo.com"]):
            if re.search(r"(paypal|microsoft|apple|amazon|ato|mygov)", from_val, re.IGNORECASE):
                issues.append("Possible display-name spoofing from free email provider")
                cls._add_breakdown(breakdown, 14, "Header", "Brand display name with free email domain")

        return issues

    # --------------------------- attachment checks ---------------------------

    @classmethod
    def detect_attachment_issues(cls, text: str, breakdown: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        issues: List[str] = []
        # Find filename-like tokens
        # e.g. invoice.pdf.exe, statement.docm, update.zip
        filename_re = re.compile(r"\b[\w\- .]{1,80}\.(?:[A-Za-z0-9]{2,5}\.)*[A-Za-z0-9]{2,5}\b")
        candidates = filename_re.findall(text)

        risky_found: List[str] = []
        double_ext_found: List[str] = []

        for name in candidates:
            parts = name.lower().strip().split(".")
            if len(parts) < 2:
                continue
            ext = parts[-1]
            prev = parts[-2] if len(parts) >= 2 else ""

            if ext in cls.RISKY_EXTENSIONS:
                risky_found.append(name.strip())
            if prev in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png"} and ext in {"exe", "js", "vbs", "scr"}:
                double_ext_found.append(name.strip())

        if double_ext_found:
            issues.append(f"Double-extension attachment name(s) detected: {', '.join(sorted(set(double_ext_found)))}")
            cls._add_breakdown(breakdown, 26, "Attachment", "Double-extension trick (e.g., .pdf.exe)")

        # risky extensions (non double-extension)
        risky_only = sorted(set(risky_found) - set(double_ext_found))
        if risky_only:
            issues.append(f"Risky attachment extension(s) detected: {', '.join(risky_only[:5])}{'...' if len(risky_only) > 5 else ''}")
            cls._add_breakdown(breakdown, 20, "Attachment", "Risky executable/archive/macro attachment")

        return issues

    # --------------------------- scoring ---------------------------

    @classmethod
    def calculate_risk_score(
        cls,
        keyword_matches: List[str],
        urls: List[Dict[str, Any]],
        sensitive: List[str],
        header_issues: List[str],
        attachment_issues: List[str],
        breakdown: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        # Start with explainable breakdown points (already weighted)
        score = 0
        if breakdown:
            score += sum(int(item.get("points", 0)) for item in breakdown)

        # Keywords provide mild signal (avoid false positives)
        # Cap keyword contribution.
        kw_points = min(len(keyword_matches) * 4, 20)
        score += kw_points
        if kw_points and breakdown is not None:
            cls._add_breakdown(breakdown, kw_points, "Keyword", f"Matched {len(keyword_matches)} keyword(s)")

        # Presence of multiple distinct categories increases confidence.
        categories = set()
        if urls:
            categories.add("url")
        if sensitive:
            categories.add("sensitive")
        if header_issues:
            categories.add("header")
        if attachment_issues:
            categories.add("attachment")
        if len(categories) >= 3:
            score += 8
            cls._add_breakdown(breakdown, 8, "Confidence", "Multiple independent phishing indicators")

        # False-positive control: if all URLs are trusted and there are no major issues,
        # slightly reduce the score.
        url_hosts = []
        for u in urls:
            try:
                h = urlparse(u.get("url", "")).netloc.split("@")[-1].split(":")[0].lower().strip(".")
            except Exception:
                h = ""
            if h:
                url_hosts.append(h)
        if url_hosts and all(cls._domain_matches_trusted(h) for h in url_hosts):
            if not sensitive and not header_issues and not attachment_issues:
                score = max(score - 10, 0)
                cls._add_breakdown(breakdown, 10, "Adjustment", "Trusted domains only (reduced score)")

        return max(0, min(int(score), 100))

    @staticmethod
    def get_risk_level(score: int) -> str:
        if score < 30:
            return "Low Risk"
        if score < 60:
            return "Medium Risk"
        return "High Risk"
