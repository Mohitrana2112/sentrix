"""
SENTRIX Domain Intelligence Module
SSL/TLS certificate inspection, HTTP security header evaluation,
passive technology fingerprinting, and WHOIS registration metadata.
"""

import ssl
import socket
import datetime
import certifi
import concurrent.futures
from typing import Dict, Any, Optional, List
import whois
from modules.ssrf_guard import validate_hostname_safe, safe_http_head
from modules.dns_analysis import query_dns_records


def normalize_domain_target(domain_raw: str) -> str:
    """
    Cleans URLs, protocols, ports, trailing slashes, fragments, and queries into a clean FQDN hostname.
    """
    d = (domain_raw or "").strip().lower()
    if "://" in d:
        d = d.split("://")[1]
    # Strip paths, queries, fragments, ports
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip()
    return d


def inspect_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Connects via TLS and extracts x509 certificate metadata, validity dates,
    subject alternative names, cipher suites, and expiry countdown.
    """
    clean_host = normalize_domain_target(hostname)
    is_safe, msg, ip = validate_hostname_safe(clean_host)
    if not is_safe:
        return {"available": False, "error": f"SSRF Guard blocked SSL connection: {msg}"}

    cert_dict = {}
    cipher = None
    tls_version = None

    try:
        # 1. Primary standard secure handshake with certifi CA bundle
        try:
            ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ctx = ssl.create_default_context()

        # Resolve host to IPv4 to avoid Windows IPv6 connection timeouts
        connect_target = clean_host
        try:
            connect_target = socket.gethostbyname(clean_host)
        except Exception:
            connect_target = clean_host

        try:
            with socket.create_connection((connect_target, port), timeout=4.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert_dict = ssock.getpeercert() or {}
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
        except (ssl.SSLCertVerificationError, ssl.SSLError):
            # Fallback for self-signed or unverified certificates
            ctx_unverified = ssl._create_unverified_context()
            ctx_unverified.check_hostname = False
            ctx_unverified.verify_mode = ssl.CERT_NONE
            with socket.create_connection((connect_target, port), timeout=4.0) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

        # Extract dates
        not_before = cert_dict.get("notBefore")
        not_after = cert_dict.get("notAfter")
        days_remaining = None
        is_expired = False

        if not_after:
            try:
                # Format example: 'May 20 12:00:00 2026 GMT'
                expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                remaining_delta = expiry_dt - datetime.datetime.utcnow()
                days_remaining = remaining_delta.days
                if days_remaining < 0:
                    is_expired = True
            except Exception:
                pass

        # Extract Issuer & Subject
        subject = {}
        issuer = {}
        for item in cert_dict.get("subject", ()):
            for key, val in item:
                subject[key] = val
        for item in cert_dict.get("issuer", ()):
            for key, val in item:
                issuer[key] = val

        # Subject Alternative Names (SANs)
        sans = []
        for typ, name in cert_dict.get("subjectAltName", ()):
            if typ == "DNS":
                sans.append(name)

        has_cert = bool(cert_dict or cipher)

        return {
            "available": has_cert,
            "subject": subject,
            "common_name": subject.get("commonName", clean_host),
            "issuer": issuer,
            "issuer_name": issuer.get("organizationName") or issuer.get("commonName") or "Public CA / Encrypted Endpoint",
            "valid_from": not_before or "N/A",
            "valid_to": not_after or "N/A",
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "sans": sans[:15],
            "total_sans": len(sans),
            "cipher": cipher[0] if cipher else "Unknown",
            "tls_version": tls_version or "TLS 1.2/1.3",
            "bits": cipher[2] if cipher and len(cipher) > 2 else 256
        }
    except Exception as e:
        return {
            "available": False,
            "error": f"TLS handshake failed: {str(e)}"
        }


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Evaluates defensive HTTP security headers and grades baseline posture.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    checks = {
        "Strict-Transport-Security": {
            "present": "strict-transport-security" in headers_lower,
            "value": headers_lower.get("strict-transport-security"),
            "importance": "High",
            "desc": "Forces browsers to exclusively use HTTPS connections."
        },
        "Content-Security-Policy": {
            "present": "content-security-policy" in headers_lower,
            "value": (headers_lower.get("content-security-policy") or "")[:120] + ("..." if len(headers_lower.get("content-security-policy") or "") > 120 else ""),
            "importance": "Critical",
            "desc": "Mitigates Cross-Site Scripting (XSS) and data injection attacks."
        },
        "X-Frame-Options": {
            "present": "x-frame-options" in headers_lower,
            "value": headers_lower.get("x-frame-options"),
            "importance": "Medium",
            "desc": "Prevents Clickjacking by disallowing iframe embedding."
        },
        "X-Content-Type-Options": {
            "present": "x-content-type-options" in headers_lower,
            "value": headers_lower.get("x-content-type-options"),
            "importance": "Medium",
            "desc": "Prevents MIME-sniffing away from the declared content-type."
        },
        "Referrer-Policy": {
            "present": "referrer-policy" in headers_lower,
            "value": headers_lower.get("referrer-policy"),
            "importance": "Low",
            "desc": "Controls referrer information passed in link requests."
        },
        "Permissions-Policy": {
            "present": "permissions-policy" in headers_lower,
            "value": (headers_lower.get("permissions-policy") or "")[:80],
            "importance": "Low",
            "desc": "Restricts browser features like camera, microphone, and geolocation."
        }
    }

    present_count = sum(1 for c in checks.values() if c["present"])
    header_score = int((present_count / len(checks)) * 100)

    # Passive tech identification
    tech = {
        "server": headers_lower.get("server", "Hidden/Custom"),
        "powered_by": headers_lower.get("x-powered-by", None),
        "cdn": "Cloudflare" if "cf-ray" in headers_lower else ("AWS CloudFront" if "x-amz-cf-id" in headers_lower else None)
    }

    return {
        "score": header_score,
        "present_count": present_count,
        "total_count": len(checks),
        "headers": checks,
        "technologies": tech
    }


def query_whois_safe(domain: str, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Retrieves WHOIS registration records safely with a strict socket timeout fallback.
    """
    clean_domain = normalize_domain_target(domain)
    if not clean_domain:
        return {"available": False, "error": "Empty domain provided."}

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        w = whois.whois(clean_domain)

        # Convert date objects to ISO strings
        def format_date(d):
            if isinstance(d, list):
                d = d[0] if d else None
            if isinstance(d, (datetime.datetime, datetime.date)):
                return d.strftime("%Y-%m-%d %H:%M:%S")
            return str(d) if d else "N/A"

        registrar = w.registrar if hasattr(w, "registrar") else "N/A"
        creation_date = format_date(getattr(w, "creation_date", None))
        expiration_date = format_date(getattr(w, "expiration_date", None))
        updated_date = format_date(getattr(w, "updated_date", None))
        status = getattr(w, "status", None)
        if isinstance(status, list):
            status = status[0] if status else "Active"
        
        emails = getattr(w, "emails", None)
        if isinstance(emails, list):
            emails = emails[0] if emails else "Redacted"

        return {
            "available": True,
            "registrar": registrar or "N/A",
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "status": str(status or "Active"),
            "contact_email": str(emails or "Privacy Redacted"),
            "country": getattr(w, "country", "N/A") or "N/A"
        }
    except Exception as e:
        return {
            "available": False,
            "error": f"WHOIS lookup unavailable or rate-limited: {str(e)}"
        }
    finally:
        try:
            socket.setdefaulttimeout(old_timeout)
        except Exception:
            pass


def investigate_domain_complete(domain: str) -> Dict[str, Any]:
    """
    Comprehensive Domain Intelligence aggregator with concurrent asynchronous execution:
    DNS records, SSL/TLS certificates, HTTP security headers, and WHOIS.
    """
    clean_domain = normalize_domain_target(domain)
    if not clean_domain:
        return {
            "success": False,
            "error": "Invalid or empty domain specified.",
            "domain": domain
        }

    # Parallelize audits via ThreadPoolExecutor for high-speed resolution
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    f_dns = executor.submit(query_dns_records, clean_domain)
    f_ssl = executor.submit(inspect_ssl_certificate, clean_domain)

    def _fetch_headers():
        http_result = safe_http_head(f"https://{clean_domain}")
        if not http_result.get("success"):
            http_result = safe_http_head(f"http://{clean_domain}")
        return analyze_security_headers(http_result.get("headers", {}))

    f_headers = executor.submit(_fetch_headers)
    f_whois = executor.submit(query_whois_safe, clean_domain, 3.5)

    # Collect DNS
    try:
        dns_data = f_dns.result(timeout=6.0)
    except Exception as e:
        dns_data = {
            "domain": clean_domain, "query_time_ms": 0,
            "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "PTR": []},
            "security_features": {"has_spf": False, "has_dmarc": False, "dmarc_record": None, "spf_record": None, "dnssec_present": False},
            "total_records_found": 0, "errors": [f"DNS query error: {str(e)}"]
        }

    # Collect SSL
    try:
        ssl_data = f_ssl.result(timeout=6.0)
    except Exception as e:
        ssl_data = {"available": False, "error": f"SSL inspection error: {str(e)}"}

    # Collect Headers
    try:
        headers_data = f_headers.result(timeout=6.0)
    except Exception as e:
        headers_data = {
            "score": 0, "present_count": 0, "total_count": 6,
            "headers": {}, "technologies": {"server": "Unknown", "powered_by": None, "cdn": None}
        }

    # Collect WHOIS
    try:
        whois_data = f_whois.result(timeout=5.0)
    except Exception as e:
        whois_data = {"available": False, "error": f"WHOIS error: {str(e)}"}

    try:
        executor.shutdown(wait=False)
    except Exception:
        pass

    # Posture Risk Calculation
    risk_factors = []
    if ssl_data.get("is_expired"):
        risk_factors.append("SSL Certificate is expired.")
    if not ssl_data.get("available"):
        risk_factors.append("No valid SSL/TLS certificate discovered.")
    if headers_data.get("score", 0) < 40:
        risk_factors.append(f"Weak HTTP security header posture ({headers_data.get('score', 0)}%).")
    if not dns_data.get("security_features", {}).get("has_dmarc"):
        risk_factors.append("Missing DMARC email spoofing protection policy.")

    return {
        "success": True,
        "domain": clean_domain,
        "dns": dns_data,
        "ssl": ssl_data,
        "headers": headers_data,
        "whois": whois_data,
        "posture": {
            "header_score": headers_data.get("score", 0),
            "tls_active": ssl_data.get("available", False),
            "risk_factors": risk_factors
        }
    }
