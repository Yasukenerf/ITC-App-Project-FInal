from backend.app.services.phishing_analyzer import PhishingAnalyzer


def test_empty_is_low_risk():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    r = a.analyze("")
    assert r.score == 0
    assert r.level == "Low Risk"


def test_detects_http_shortener_and_sensitive_request():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    email = "Please verify your account here http://bit.ly/abc and send your password"
    r = a.analyze(email)
    assert r.score > 0
    assert any("Non-secure HTTP" in issue for u in r.urls for issue in u["issues"])
    assert any("URL shortener" in issue for u in r.urls for issue in u["issues"])
    assert any("Password" in s for s in r.sensitive)


def test_detects_ip_url_and_at_trick():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    email = "Reset your password: http://user:pass@185.12.34.56/login"
    r = a.analyze(email)
    issues = [issue for u in r.urls for issue in u["issues"]]
    assert any("@" in issue for issue in issues)
    assert any("IP address" in issue for issue in issues)


def test_detects_reply_to_mismatch():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    raw = """From: PayPal Support <support@gmail.com>\nReply-To: secure@evil.example\nSubject: Action required\n\nPlease verify your account."""
    r = a.analyze(raw)
    assert any("Reply-To" in h for h in r.header_issues)


def test_detects_double_extension_attachment_name():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    email = "Please see attached invoice.pdf.exe and open it."
    r = a.analyze(email)
    assert any("Double-extension" in a for a in r.attachment_issues)


def test_flags_ip_url_and_at_trick():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    email = "Click https://paypal.com@185.10.10.10/login to verify"
    r = a.analyze(email)
    assert r.urls, "Should detect URL issues"
    flat = "\n".join(issue for u in r.urls for issue in u["issues"])
    assert "@" in flat
    assert "IP address" in flat


def test_flags_reply_to_mismatch_when_headers_present():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    raw = "From: PayPal Support <support@paypal.com>\nReply-To: support@evil-example.com\n\nPlease verify your account"
    r = a.analyze(raw)
    assert any("Reply-To" in h for h in r.header_issues)


def test_flags_double_extension_attachment_name():
    a = PhishingAnalyzer(keyword_file="src/backend/app/services/phishing_keywords.txt")
    raw = "Please see attached invoice.pdf.exe and confirm payment"
    r = a.analyze(raw)
    assert any("Double-extension" in x or "Double" in x for x in r.attachment_issues)
