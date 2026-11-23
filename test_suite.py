"""
SENTRIX Comprehensive Automated Verification Test Suite
"""

import json
from app import create_app
from database.models import Investigation
from modules.ssrf_guard import is_ip_blocked, validate_hostname_safe

def run_tests():
    app = create_app()
    client = app.test_client()

    print("======================================================================")
    print("RUNNING SENTRIX VERIFICATION & SECURITY ASSURANCE TEST SUITE")
    print("======================================================================")

    # 1. Test URL Analyzer API - Malicious Target
    resp = client.post(
        "/api/analyze-url",
        data=json.dumps({"url": "https://paypa1-secure-verification.com/login?token=xyz"}),
        content_type="application/json"
    )
    assert resp.status_code == 200, f"URL Analyzer failed: {resp.status_code}"
    data = resp.get_json()
    assert data["success"] is True
    assert data["risk"]["score"] >= 50
    assert "ip_intelligence" in data
    assert "confidence" in data["risk"]
    print(f"[*] 1. URL Analyzer API: PASSED (Risk Score: {data['risk']['score']}/100, Class: {data['risk']['classification']}, Conf: {data['risk']['confidence']})")

    # 1b. Test Scoring Engine Clean Baseline for Safe Domains (Google & GitHub)
    resp_google = client.post("/api/analyze-url", data=json.dumps({"url": "https://google.com"}), content_type="application/json")
    data_google = resp_google.get_json()
    assert data_google["risk"]["score"] == 0, f"Google.com risk score must be 0, got {data_google['risk']['score']}"
    assert data_google["risk"]["classification"] == "LOW"
    print(f"[*] 1b. Clean Baseline Verification (google.com): PASSED (Score: {data_google['risk']['score']}/100, Class: {data_google['risk']['classification']})")

    resp_github = client.post("/api/analyze-url", data=json.dumps({"url": "https://github.com"}), content_type="application/json")
    data_github = resp_github.get_json()
    assert data_github["risk"]["score"] == 0, f"Github.com risk score must be 0, got {data_github['risk']['score']}"
    assert data_github["risk"]["classification"] == "LOW"
    print(f"[*] 1c. Clean Baseline Verification (github.com): PASSED (Score: {data_github['risk']['score']}/100, Class: {data_github['risk']['classification']})")

    # 1c. Test Punycode IDN Homoglyph Spoofing (xn--pple-43d.com)
    resp_puny = client.post("/api/analyze-url", data=json.dumps({"url": "https://xn--pple-43d.com"}), content_type="application/json")
    data_puny = resp_puny.get_json()
    assert data_puny["risk"]["score"] >= 75
    assert data_puny["risk"]["classification"] == "CRITICAL"
    print(f"[*] 1d. Punycode Apple Homoglyph Detection: PASSED (Score: {data_puny['risk']['score']}/100, Class: {data_puny['risk']['classification']})")

    # 1d. Test Userinfo @ Injection (google.com@evil.xyz/login)
    resp_userinfo = client.post("/api/analyze-url", data=json.dumps({"url": "https://google.com@evil.xyz/login"}), content_type="application/json")
    data_userinfo = resp_userinfo.get_json()
    assert data_userinfo["risk"]["score"] >= 70
    print(f"[*] 1e. Embedded Userinfo (@) Phishing Detection: PASSED (Score: {data_userinfo['risk']['score']}/100)")

    # 1e. Test Raw IP SSRF Destination (http://192.168.1.1/admin)
    resp_ssrf = client.post("/api/analyze-url", data=json.dumps({"url": "http://192.168.1.1/admin"}), content_type="application/json")
    data_ssrf = resp_ssrf.get_json()
    assert data_ssrf["risk"]["score"] >= 75
    print(f"[*] 1f. Raw IP SSRF Hazard Detection: PASSED (Score: {data_ssrf['risk']['score']}/100, Class: {data_ssrf['risk']['classification']})")

    # 2. Test SSRF Guard
    blocked_loopback, _ = is_ip_blocked("127.0.0.1")
    assert blocked_loopback is True, "Loopback must be blocked"
    blocked_meta, _ = is_ip_blocked("169.254.169.254")
    assert blocked_meta is True, "AWS Metadata / link-local must be blocked"
    blocked_private, _ = is_ip_blocked("192.168.1.1")
    assert blocked_private is True, "RFC 1918 Private subnet must be blocked"
    blocked_cgnat, _ = is_ip_blocked("100.64.0.1")
    assert blocked_cgnat is True, "CGNAT must be blocked"
    print("[*] 2. SSRF Protection Guardrails: PASSED (RFC 1918, Loopback, Link-Local all blocked)")

    # 3. Test SENTRIX AI Chatbot
    resp = client.post(
        "/api/chatbot",
        data=json.dumps({"message": "What is Google Dorking and how is it used defensively?"}),
        content_type="application/json"
    )
    assert resp.status_code == 200, f"Chatbot API failed: {resp.status_code}"
    chat_data = resp.get_json()
    assert chat_data["success"] is True
    assert "Google Dork" in chat_data["reply"] or len(chat_data["reply"]) > 50
    print("[*] 3. SENTRIX AI Chatbot Engine: PASSED (Contextual reply generated)")

    # 4. Test Report Generation (PDF, CSV, TXT)
    with app.app_context():
        first_inv = Investigation.query.first()
        inv_uuid = first_inv.uuid

    resp_pdf = client.get(f"/api/download-report/{inv_uuid}?format=pdf")
    assert resp_pdf.status_code == 200
    assert resp_pdf.content_type == "application/pdf"
    assert len(resp_pdf.data) > 1000
    print(f"[*] 4. ReportLab PDF Generation: PASSED ({len(resp_pdf.data)} bytes generated)")

    resp_csv = client.get(f"/api/download-report/{inv_uuid}?format=csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.content_type
    print("[*] 5. Investigation CSV Export: PASSED")

    resp_txt = client.get(f"/api/download-report/{inv_uuid}?format=txt")
    assert resp_txt.status_code == 200
    assert "text/plain" in resp_txt.content_type
    print("[*] 6. Investigation TXT Export: PASSED")

    # 5. Test OSINT Exporters
    resp_osint_txt = client.get("/osint/export?domain=tesla.com&format=txt")
    assert resp_osint_txt.status_code == 200
    assert "SENTRIX OSINT" in resp_osint_txt.get_data(as_text=True)
    print("[*] 7. OSINT TXT Playbook Export: PASSED")

    resp_osint_csv = client.get("/osint/export?domain=tesla.com&format=csv")
    assert resp_osint_csv.status_code == 200
    print("[*] 8. OSINT CSV Matrix Export: PASSED")

    # 6. Test Settings Save
    resp_settings = client.post(
        "/settings/save",
        data={"analyst_name": "SEC-CHIEF-01", "organization": "Global Cyber CERT", "gemini_api_key": ""},
        follow_redirects=True
    )
    assert resp_settings.status_code == 200
    assert b"SEC-CHIEF-01" in resp_settings.data
    print("[*] 9. Analyst Settings Persistence: PASSED")

    # 7. Test Report Deletion Endpoint
    del_resp = client.post(f"/reports/delete/{inv_uuid}", headers={"X-Requested-With": "XMLHttpRequest"})
    assert del_resp.status_code == 200, f"Delete failed: {del_resp.status_code}"
    del_data = del_resp.get_json()
    assert del_data["success"] is True
    print("[*] 10. Investigation Report Deletion: PASSED")

    print("======================================================================")
    print("ALL 10 VERIFICATION CHECKS PASSED WITH ZERO ERRORS!")
    print("======================================================================")

if __name__ == "__main__":
    run_tests()
