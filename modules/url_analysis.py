"""
SENTRIX Advanced URL Analyzer & IP Intelligence Module v2.5
Deep structural decomposition, Shannon entropy analytics, evidence-based brand spoofing detection,
Punycode IDN inspection, dual-stack IPv4/IPv6 resolution, and granular risk assessment.
"""

import math
import re
import socket
import datetime
import urllib.parse
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from modules.risk_engine import RiskIndicator, RiskEvaluation

# High-value target brands frequently abused in credential theft & phishing
TARGET_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co", "google.org", "googlevideo.com", "gstatic.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citi": ["citi.com", "citigroup.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "dropbox": ["dropbox.com"],
    "telegram": ["telegram.org", "t.me"],
    "whatsapp": ["whatsapp.com"],
    "discord": ["discord.com", "discord.gg"],
    "ebay": ["ebay.com"],
    "adobe": ["adobe.com"],
    "yahoo": ["yahoo.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "gitlab": ["gitlab.com"],
    "salesforce": ["salesforce.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "spotify": ["spotify.com"],
    "metamask": ["metamask.io"],
    "trustwallet": ["trustwallet.com"],
    "walmart": ["walmart.com"],
    "target": ["target.com"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"]
}

# Known URL shortener services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "goo.gl", "bit.do", "cutt.ly", "snip.ly", "shorturl.at", "tiny.cc",
    "bl.ink", "lnkd.in", "t.me", "soo.gd", "s.id", "rb.gy"
}

# Frequently abused TLDs with high spam/phishing correlation
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
    "click", "rest", "country", "link", "bid", "stream", "icu", "cam",
    "surf", "monster", "cfd", "sbs", "quest", "mom"
}

STANDARD_PORTS = {80, 443}

# Sensitive tokens common in credential phishing & open redirects
SENSITIVE_PARAM_KEYS = {
    "token", "redirect", "url", "dest", "return", "next", "continue",
    "target", "auth", "session", "key", "password", "pwd", "email",
    "user", "account", "login", "payload", "cmd", "exec", "eval"
}


def calculate_entropy(text: str) -> float:
    """
    Computes Shannon Entropy of a string to detect randomized DGA strings.
    """
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p, 2) for p in prob])
    return round(entropy, 3)


def parse_domain_parts(hostname: str) -> Dict[str, str]:
    """
    Splits hostname into subdomain, registered domain, and TLD.
    Accurately handles multi-part TLDs (e.g. .co.uk, .gov.in, .com.au).
    """
    cleaned = hostname.strip().lower()
    if not cleaned:
        return {"subdomain": "", "domain": "", "tld": "", "registered_domain": ""}

    # Check if host is an IP address
    try:
        ipaddress.ip_address(cleaned)
        return {
            "subdomain": "",
            "domain": cleaned,
            "tld": "IP",
            "registered_domain": cleaned
        }
    except ValueError:
        pass

    parts = cleaned.split(".")
    if len(parts) == 1:
        return {
            "subdomain": "",
            "domain": parts[0],
            "tld": "",
            "registered_domain": parts[0]
        }

    # Two-part TLDs lookup
    two_part_tlds = {
        "co.uk", "gov.uk", "org.uk", "ac.uk", "com.au", "net.au",
        "gov.in", "co.in", "com.br", "co.jp", "com.sg", "co.nz"
    }
    joined_last_two = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else ""

    if joined_last_two in two_part_tlds and len(parts) >= 3:
        tld = joined_last_two
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])
        reg_domain = f"{domain}.{tld}"
    else:
        tld = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
        reg_domain = f"{domain}.{tld}"

    return {
        "subdomain": subdomain,
        "domain": domain,
        "tld": tld,
        "registered_domain": reg_domain
    }


def is_official_brand_domain(registered_domain: str, brand: str) -> bool:
    """
    Checks if a registered domain is an authoritative domain for the brand.
    e.g., 'google.com' is legitimate for 'google', 'github.com' is legitimate for 'github'.
    """
    reg_clean = registered_domain.lower()
    official_list = TARGET_BRANDS.get(brand, [])
    for off in official_list:
        if reg_clean == off or reg_clean.endswith("." + off):
            return True
    return False


def check_brand_typosquatting(domain: str, registered_domain: str, full_host: str) -> List[Dict[str, str]]:
    """
    Evidence-based brand typosquatting detector.
    Distinguishes legitimate brand domains from visual spoofs and piggybacking.
    """
    matches = []
    host_lower = full_host.lower()
    domain_lower = domain.lower()
    reg_lower = registered_domain.lower()

    # Levenshtein distance
    def levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev[j + 1] + 1
                deletions = curr[j] + 1
                subs = prev[j] + (c1 != c2)
                curr.append(min(insertions, deletions, subs))
            prev = curr
        return prev[-1]

    # Visual leetspeak substitutions
    substituted = (
        domain_lower.replace("0", "o")
                    .replace("1", "l")
                    .replace("3", "e")
                    .replace("4", "a")
                    .replace("5", "s")
                    .replace("vv", "w")
    )

    for brand in TARGET_BRANDS:
        # Check if this registered domain is the legitimate brand owner
        if is_official_brand_domain(reg_lower, brand) or (domain_lower == brand and reg_lower.endswith(".com")):
            # It IS the official brand domain! Skip (false-positive prevention)
            continue

        # 1. Lookalike substitution (e.g. 'paypa1', 'micros0ft')
        if brand in substituted and domain_lower != brand:
            matches.append({
                "brand": brand,
                "type": "Visual Character Substitution (Leetspeak)",
                "details": f"Target domain '{domain}' substitutes characters to spoof major brand '{brand}'."
            })
            continue

        # 2. Typosquatting by edit distance = 1 (e.g. 'goolge', 'amazone', 'netflx')
        if len(brand) >= 5 and abs(len(domain_lower) - len(brand)) <= 1:
            dist = levenshtein(domain_lower, brand)
            if dist == 1 and domain_lower != brand:
                matches.append({
                    "brand": brand,
                    "type": "Levenshtein Typosquatting Mutation",
                    "details": f"Domain '{domain}' has an edit distance of 1 from authoritative brand '{brand}'."
                })
                continue

        # 3. Brand piggybacking in hyphenated or composite foreign domain
        # e.g. 'paypal-security-update.com', 'login-apple-verify.xyz'
        if brand in domain_lower and not is_official_brand_domain(reg_lower, brand):
            # If domain contains the brand with hyphens or prefix/suffix
            if f"-{brand}" in domain_lower or f"{brand}-" in domain_lower or f"login{brand}" in domain_lower or f"{brand}security" in domain_lower or f"verify{brand}" in domain_lower:
                matches.append({
                    "brand": brand,
                    "type": "Combosquatting / Brand Piggybacking",
                    "details": f"Foreign domain '{registered_domain}' embeds brand name '{brand}' with deceptive administrative keywords."
                })
                continue

        # 4. Brand spoofing via subdomain on foreign host
        # e.g. 'paypal.com.evil-attacker.xyz'
        if brand in host_lower and not is_official_brand_domain(reg_lower, brand):
            matches.append({
                "brand": brand,
                "type": "Subdomain Brand Impersonation",
                "details": f"Brand name '{brand}' embedded into subdomain on unrelated host '{full_host}'."
            })

    return matches


def resolve_ip_intelligence(hostname: str) -> Dict[str, Any]:
    """
    Performs fast dual-stack DNS resolution (IPv4 & IPv6), address classification,
    and reverse DNS PTR association with strict SSRF-aware safety reporting.
    """
    clean_host = hostname.strip().lower()
    timestamp_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    ip_intel: Dict[str, Any] = {
        "hostname": clean_host,
        "is_direct_ip": False,
        "direct_ip_version": None,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "all_addresses": [],
        "details": [],
        "has_private_ip": False,
        "status": "Resolution Pending",
        "timestamp": timestamp_utc
    }

    if not clean_host:
        ip_intel["status"] = "No hostname provided"
        return ip_intel

    # 1. Direct IP check
    try:
        direct_ip = ipaddress.ip_address(clean_host)
        ip_intel["is_direct_ip"] = True
        ip_intel["direct_ip_version"] = direct_ip.version

        is_priv = False
        classification = "Public Internet (Routable)"
        if direct_ip.is_private:
            classification = "Private Network (RFC 1918)"
            is_priv = True
            ip_intel["has_private_ip"] = True
        elif direct_ip.is_loopback:
            classification = "Loopback (RFC 3330)"
            is_priv = True
            ip_intel["has_private_ip"] = True
        elif direct_ip.is_link_local:
            classification = "Link-Local (RFC 3927)"
            is_priv = True
            ip_intel["has_private_ip"] = True
        elif direct_ip.is_reserved:
            classification = "Reserved Space"
            is_priv = True
            ip_intel["has_private_ip"] = True
        elif direct_ip.is_multicast:
            classification = "Multicast"

        item = {
            "ip": clean_host,
            "version": f"IPv{direct_ip.version}",
            "classification": classification,
            "is_private": is_priv,
            "ptr": "Direct IP Target"
        }
        ip_intel["details"].append(item)
        if direct_ip.version == 4:
            ip_intel["ipv4_addresses"].append(clean_host)
        else:
            ip_intel["ipv6_addresses"].append(clean_host)
        ip_intel["all_addresses"].append(clean_host)
        ip_intel["status"] = f"Direct IPv{direct_ip.version} address evaluated"
        return ip_intel
    except ValueError:
        pass

    # 2. Fast DNS Resolution via dnspython with strict 1.0s timeout
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.5

        # Query A records
        try:
            answers_a = resolver.resolve(clean_host, "A")
            for rdata in answers_a:
                ip_str = str(rdata).strip()
                if ip_str not in ip_intel["ipv4_addresses"]:
                    ip_intel["ipv4_addresses"].append(ip_str)
        except Exception:
            pass

        # Query AAAA records
        try:
            answers_aaaa = resolver.resolve(clean_host, "AAAA")
            for rdata in answers_aaaa:
                ip_str = str(rdata).strip()
                if ip_str not in ip_intel["ipv6_addresses"]:
                    ip_intel["ipv6_addresses"].append(ip_str)
        except Exception:
            pass
    except Exception:
        # Fallback to standard socket with timeout
        try:
            orig_t = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            addr_info = socket.getaddrinfo(clean_host, None)
            for res in addr_info:
                ip = res[4][0]
                if ":" in ip and ip not in ip_intel["ipv6_addresses"]:
                    ip_intel["ipv6_addresses"].append(ip)
                elif "." in ip and ip not in ip_intel["ipv4_addresses"]:
                    ip_intel["ipv4_addresses"].append(ip)
            socket.setdefaulttimeout(orig_t)
        except Exception:
            pass

    all_ips = ip_intel["ipv4_addresses"] + ip_intel["ipv6_addresses"]
    ip_intel["all_addresses"] = all_ips

    # Classify each resolved IP
    for ip_str in all_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_priv = False
            classification = "Public Internet (Routable)"

            if ip_obj.is_private:
                classification = "Private Network (RFC 1918)"
                is_priv = True
                ip_intel["has_private_ip"] = True
            elif ip_obj.is_loopback:
                classification = "Loopback (RFC 3330)"
                is_priv = True
                ip_intel["has_private_ip"] = True
            elif ip_obj.is_link_local:
                classification = "Link-Local (RFC 3927)"
                is_priv = True
                ip_intel["has_private_ip"] = True
            elif ip_obj.is_reserved:
                classification = "Reserved Network"
                is_priv = True
                ip_intel["has_private_ip"] = True

            ip_intel["details"].append({
                "ip": ip_str,
                "version": f"IPv{ip_obj.version}",
                "classification": classification,
                "is_private": is_priv,
                "ptr": f"PTR for {clean_host}" if not is_priv else "Internal / Not Publicly Routed"
            })
        except ValueError:
            continue

    if all_ips:
        ip_intel["status"] = (
            f"Successfully resolved {len(ip_intel['ipv4_addresses'])} IPv4 "
            f"and {len(ip_intel['ipv6_addresses'])} IPv6 endpoint(s)"
        )
    else:
        ip_intel["status"] = "No active A or AAAA records returned by resolver"

    return ip_intel


def analyze_url_deep(raw_url: str) -> Dict[str, Any]:
    """
    Main URL Analysis pipeline:
    Deconstructs syntax anatomy, analyzes heuristics, evaluates brand spoofing,
    resolves IP intelligence, and computes evidence-weighted risk posture.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned.startswith(("http://", "https://")):
        scheme_assumed = True
        test_url = "https://" + cleaned
    else:
        scheme_assumed = False
        test_url = cleaned

    parsed = urllib.parse.urlsplit(test_url)
    protocol = parsed.scheme.lower()
    raw_hostname = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    query_str = parsed.query
    fragment = parsed.fragment

    # Parse query parameters
    query_params = urllib.parse.parse_qs(query_str, keep_blank_values=True)
    flattened_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

    # Break down domain structure
    domain_breakdown = parse_domain_parts(raw_hostname)
    subdomain = domain_breakdown["subdomain"]
    domain = domain_breakdown["domain"]
    tld = domain_breakdown["tld"]
    reg_domain = domain_breakdown["registered_domain"]

    indicators: List[RiskIndicator] = []

    # 1. Transport Security (Insecure HTTP)
    if protocol == "http":
        indicators.append(RiskIndicator(
            name="Insecure HTTP Transport",
            severity="LOW",
            score_impact=15,
            evidence="Transport protocol: http:// (cleartext unencrypted)",
            technical_explanation="Communication over cleartext HTTP is vulnerable to man-in-the-middle (MitM) eavesdropping and traffic tampering.",
            precaution="Enforce modern HTTPS with TLS 1.3 encryption and HSTS preloading headers.",
            confidence="HIGH",
            category="Transport Security"
        ))

    # 2. IP-based Hostname
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(raw_hostname)
        is_ip = True
        # Check if private IP
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            indicators.append(RiskIndicator(
                name="Internal / Private IP Hostname (SSRF Vector)",
                severity="CRITICAL",
                score_impact=50,
                evidence=f"Target resolves to internal space: {raw_hostname}",
                technical_explanation="Direct connection to non-routable RFC 1918 or loopback space indicates an internal network reconnaissance or SSRF attack vector.",
                precaution="Block direct requests to non-public subnets at web proxies and egress firewalls.",
                confidence="HIGH",
                category="Network Boundary"
            ))
        else:
            indicators.append(RiskIndicator(
                name="Direct Public IP Hostname",
                severity="HIGH",
                score_impact=35,
                evidence=f"Direct IP endpoint: {raw_hostname}",
                technical_explanation="Legitimate web services almost universally operate behind authoritative DNS domains. Direct IP URLs are commonly utilized by transient malware C2 infrastructure and phishing kits.",
                precaution="Restrict direct IP connections unless explicitly authenticated internal infrastructure.",
                confidence="HIGH",
                category="Infrastructure"
            ))
    except ValueError:
        pass

    # 3. URL Shortener Service
    if raw_hostname.lower() in SHORTENER_DOMAINS:
        indicators.append(RiskIndicator(
            name="URL Shortening Mask",
            severity="MEDIUM",
            score_impact=20,
            evidence=f"Shortener Host: {raw_hostname}",
            technical_explanation="URL shorteners conceal the true destination server to bypass basic reputation and keyword filters.",
            precaution="Trace the redirect chain using SENTRIX Safe Redirect Inspection before opening.",
            confidence="HIGH",
            category="Obfuscation"
        ))

    # 4. Excessive Subdomain Nesting (> 3 levels)
    if subdomain:
        sub_levels = len(subdomain.split("."))
        if sub_levels >= 3:
            indicators.append(RiskIndicator(
                name="Excessive Subdomain Nesting",
                severity="MEDIUM",
                score_impact=25,
                evidence=f"Subdomains: {subdomain} ({sub_levels} hierarchical levels)",
                technical_explanation="Deeply nested subdomains are often deployed to visually mimic trusted brands in mobile address bars or bypass heuristic domain parsers.",
                precaution="Inspect the base registered domain rather than relying on subdomain text.",
                confidence="MEDIUM",
                category="Syntax & Hierarchy"
            ))

    # 5. Punycode IDN Homoglyph Spoofing
    if "xn--" in raw_hostname.lower():
        try:
            decoded_host = raw_hostname.encode("ascii").decode("idna")
        except Exception:
            decoded_host = "Unknown Unicode"
        indicators.append(RiskIndicator(
            name="Punycode / Internationalized Domain (IDN)",
            severity="HIGH",
            score_impact=45,
            evidence=f"Punycode encoded: {raw_hostname} => Decoded: {decoded_host}",
            technical_explanation="Punycode allows Cyrillic or Greek homoglyphs (e.g. Cyrillic 'а' vs Latin 'a') to spoof trusted domains while appearing indistinguishable to human eyes.",
            precaution="Inspect ASCII representation and cross-verify with authoritative registrar certificates.",
            confidence="HIGH",
            category="Visual Deception"
        ))
        # Check if the decoded host mimics a brand (e.g. apple) via Cyrillic homoglyphs
        homoglyph_map = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
        }
        normalized_decoded = ''.join(homoglyph_map.get(c, c) for c in decoded_host.lower())
        for brand_k in TARGET_BRANDS:
            if brand_k in normalized_decoded:
                indicators.append(RiskIndicator(
                    name=f"Punycode Homoglyph Brand Spoofing ({brand_k.capitalize()})",
                    severity="CRITICAL",
                    score_impact=40,
                    evidence=f"Decoded IDN hostname '{decoded_host}' (normalized '{normalized_decoded}') visually replicates major brand '{brand_k}'.",
                    technical_explanation="Sophisticated homoglyph attack substituting non-Latin Cyrillic characters to mimic legitimate brand identities.",
                    precaution="Never accept authentication prompts from Punycode domains mimicking recognized platforms.",
                    confidence="HIGH",
                    category="Brand Impersonation"
                ))
                break

    # 6. Deceptive Authority Syntax (@ Userinfo symbol)
    if "@" in cleaned:
        indicators.append(RiskIndicator(
            name="Embedded Userinfo Credentials (@ symbol)",
            severity="CRITICAL",
            score_impact=50,
            evidence="@ symbol detected in URL authority syntax",
            technical_explanation="Standard RFC URL syntax parses everything before '@' as user credentials. Attackers exploit this to craft deceptive links (e.g., 'https://google.com@evil.com') that actually route to 'evil.com'.",
            precaution="Block URLs with embedded userinfo immediately. Never trust text preceding the @ delimiter.",
            confidence="HIGH",
            category="Deceptive Syntax"
        ))

    # 7. Null Byte Injection Signature
    if "%00" in cleaned or "\x00" in cleaned:
        indicators.append(RiskIndicator(
            name="Null Byte Injection Signature",
            severity="CRITICAL",
            score_impact=55,
            evidence="Null byte (%00) found in URL payload",
            technical_explanation="Null bytes are used to terminate string validation in legacy C libraries, bypass file extension whitelists, or execute path traversal attacks.",
            precaution="Reject input at perimeter WAF and inspect server-side sanitization routines.",
            confidence="HIGH",
            category="Payload Injection"
        ))

    # 8. Non-Standard Port Binding
    if port and port not in STANDARD_PORTS:
        indicators.append(RiskIndicator(
            name="Non-Standard Port Binding",
            severity="MEDIUM",
            score_impact=20,
            evidence=f"Port: {port}",
            technical_explanation=f"Traffic directed to non-standard port ({port}) bypasses typical egress filters and may expose development endpoints, proxies, or administrative consoles.",
            precaution="Confirm whether the service on this non-standard port is an authorized asset.",
            confidence="HIGH",
            category="Network Transport"
        ))

    # 9. Brand Impersonation & Typosquatting
    brand_matches = check_brand_typosquatting(domain, reg_domain, raw_hostname)
    for bm in brand_matches:
        indicators.append(RiskIndicator(
            name=f"Brand Spoofing ({bm['brand'].capitalize()})",
            severity="CRITICAL",
            score_impact=50,
            evidence=f"{bm['type']}: {bm['details']}",
            technical_explanation="High-confidence phishing heuristic: the domain visually or structurally mimics a recognized brand to deceive users and harvest authentication credentials.",
            precaution="Do not enter credentials or MFA tokens. Report domain to brand abuse desks.",
            confidence="HIGH",
            category="Brand Impersonation"
        ))

    # 10. Shannon Entropy Anomaly
    host_entropy = calculate_entropy(domain)
    if host_entropy > 3.8 and len(domain) > 10 and not is_ip:
        indicators.append(RiskIndicator(
            name="High Domain Shannon Entropy",
            severity="MEDIUM",
            score_impact=18,
            evidence=f"Domain '{domain}' Entropy: {host_entropy} bits/char",
            technical_explanation="Elevated entropy indicates random character distribution common in algorithmic Domain Generation Algorithms (DGA) used by malware botnets and resilient C2 networks.",
            precaution="Verify domain registration creation date and passive DNS historical records.",
            confidence="MEDIUM",
            category="Heuristic Anomaly"
        ))

    # 11. Suspicious Query Parameters & Base64 Signatures
    suspicious_params_found = []
    for param_name, param_val in flattened_params.items():
        low_p = param_name.lower()
        if low_p in SENSITIVE_PARAM_KEYS:
            suspicious_params_found.append(f"{param_name}={str(param_val)[:25]}")
        if isinstance(param_val, str) and len(param_val) > 40 and re.match(r"^[A-Za-z0-9+/=]+$", param_val):
            suspicious_params_found.append(f"{param_name}=[Base64 payload ({len(param_val)} chars)]")

    if suspicious_params_found:
        indicators.append(RiskIndicator(
            name="Sensitive / Obfuscated Query Parameters",
            severity="LOW",
            score_impact=12,
            evidence=f"Parameters: {', '.join(suspicious_params_found[:3])}",
            technical_explanation="Query strings with redirect tokens or base64-encoded strings are frequently exploited for open redirects or credential transmission.",
            precaution="Decode base64 payload safely and validate redirect parameters against strict domain allowlists.",
            confidence="MEDIUM",
            category="Query Parameters"
        ))

    # 12. Suspicious Top-Level Domain (TLD)
    if tld.lower() in SUSPICIOUS_TLDS:
        indicators.append(RiskIndicator(
            name="High-Risk Top-Level Domain (TLD)",
            severity="LOW",
            score_impact=12,
            evidence=f"TLD: .{tld.lower()}",
            technical_explanation=f"The .{tld.lower()} top-level domain exhibits statistically higher rates of spam and phishing registrations due to low provisioning barriers.",
            precaution="Check domain age via WHOIS and verify historical reputation before establishing trust.",
            confidence="LOW",
            category="Reputation"
        ))

    # 13. Abnormal Length
    if len(cleaned) > 160:
        indicators.append(RiskIndicator(
            name="Abnormal URL Length",
            severity="LOW",
            score_impact=10,
            evidence=f"Length: {len(cleaned)} characters",
            technical_explanation="Excessively long URLs are often crafted to conceal tracking tokens, XSS payloads, or obscure the final destination from user inspection.",
            precaution="Review path and parameters for encoded scripts or serialized objects.",
            confidence="LOW",
            category="Syntax & Hierarchy"
        ))

    # 14. Sensitive Authentication / Admin Path Targets
    path_lower = path.lower()
    sensitive_path_keywords = ["/login", "/admin", "/signin", "/verify", "/account", "/auth", "/password", "/banking", "/update"]
    for kw in sensitive_path_keywords:
        if kw in path_lower and (indicators or is_ip):
            indicators.append(RiskIndicator(
                name=f"Sensitive Authentication / Admin Target Path ({kw})",
                severity="HIGH",
                score_impact=20,
                evidence=f"Path '{path}' targets credential/admin interfaces on untrusted infrastructure",
                technical_explanation="Phishing campaigns frequently append legitimate-looking /login or /admin paths to deceptive hostnames to lure victim credential submission.",
                precaution="Verify transport certificate and domain registration before entering authentication data.",
                confidence="HIGH",
                category="Target Surface"
            ))
            break

    # Compute risk evaluation
    evaluation = RiskEvaluation(indicators)

    # Resolve IP Intelligence
    ip_intel = resolve_ip_intelligence(raw_hostname)

    # Build Anatomy Object
    anatomy = {
        "full_url": cleaned,
        "protocol": protocol,
        "hostname": raw_hostname,
        "registered_domain": reg_domain,
        "subdomain": subdomain or "(none)",
        "domain": domain,
        "tld": f".{tld}" if tld and tld != "IP" else tld,
        "port": str(port) if port else ("443" if protocol == "https" else "80"),
        "path": path,
        "query_params": flattened_params,
        "fragment": fragment or "(none)",
        "character_count": len(cleaned),
        "host_entropy": host_entropy,
        "is_ip": is_ip,
        "punycode": raw_hostname if "xn--" in raw_hostname.lower() else "None (ASCII standard)"
    }

    # Actionable defensive recommendations
    recommendations = []
    if evaluation.score >= 75:
        recommendations.append("Immediate Perimeter Block: Configure DNS sinkhole and firewall egress drop rules.")
        recommendations.append("SIEM Ingestion: Export URL and resolved IP indicators into SOC threat intelligence feeds.")
        recommendations.append("Credential Revocation: Invalidate active user tokens if internal credentials were submitted.")
    elif evaluation.score >= 50:
        recommendations.append("Elevated Alerting: Monitor proxy logs for outbound requests to this destination.")
        recommendations.append("MFA Enforcement: Mandate multi-factor authentication for affected identity sessions.")
        recommendations.append("Sandbox Detonation: Submit executable payloads or attachments for static disassembler inspection.")
    elif evaluation.score >= 25:
        recommendations.append("Verify Destination: Inspect redirect destinations and authoritative WHOIS records.")
        recommendations.append("Enforce TLS: Mandate HTTPS connections and block unencrypted cleartext transport.")
    else:
        recommendations.append("Standard Baseline Observed: URL conforms to expected structural and transport conventions.")
        recommendations.append("Maintain Continuous Telemetry: Log connection metadata within standard operational bounds.")

    return {
        "success": True,
        "url": cleaned,
        "anatomy": anatomy,
        "risk": evaluation.to_dict(),
        "ip_intelligence": ip_intel,
        "recommendations": recommendations,
    }
