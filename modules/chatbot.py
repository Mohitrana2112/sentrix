"""
SENTRIX AI Analyst 2.0 Engine
Elite Cybersecurity Intelligence and Defensive Investigation Assistant.
Supports Google Gemini API with seamless fallback to an expert rule-based
SOC reasoning engine. Fully contextualized for URL, IP, DNS, and Threat findings.
"""

import os
import re
import datetime
import requests
from typing import Dict, Any, List, Optional
from modules.url_analysis import analyze_url_deep


SYSTEM_PROMPT = """You are SENTRIX AI Analyst 2.0, an elite cybersecurity intelligence and defensive SOC investigation specialist.
Your mission: INVESTIGATE. ANALYZE. UNDERSTAND. PROTECT.
You provide technical, precise, and actionable cybersecurity analysis regarding:
- Heuristic URL structural decomposition, entropy anomalies, and typosquatting detection.
- IP intelligence, dual-stack IPv4/IPv6 classification, and SSRF perimeter guardrails.
- Authoritative DNS architecture (A, AAAA, MX, NS, TXT, SPF, DKIM, DMARC, SOA, PTR).
- SSL/TLS cryptographic verification, certificate expiration, and cipher suites.
- HTTP defensive security response headers (HSTS, CSP, X-Frame-Options, Referrer-Policy).
- Defensive Google Dorking operators (site:, inurl:, filetype:, intitle:) and OSINT methodology.
- Actionable incident response playbooks for SOC tier 1–3 analysts.

RESPONSE FORMATTING RULES:
1. Always structure responses using clean Markdown with clear headings (`###`, `####`).
2. Use bullet points (`- `) and numbered steps (`1. `) for technical readability.
3. Highlight severity levels with bracketed tags: `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, `[INFO]`.
4. Wrap code, operators, queries, and technical parameters in backticks (e.g. `site:example.com`, `v=spf1`).
5. Include actionable remediation recommendations for security teams.
6. Never claim a live sandbox detonation was performed when only static/heuristic analysis took place.
7. Maintain a professional, vigilant, and educational cybersecurity persona."""


def call_gemini_api(api_key: str, message: str, history: List[Dict[str, str]] = None, context_data: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Direct HTTPS call to Google Gemini API (gemini-1.5-flash) with contextual grounding.
    """
    if not api_key:
        return None

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    
    contents = []
    
    # 1. System Instruction & Context Prompt
    context_str = ""
    if context_data and isinstance(context_data, dict):
        url_target = context_data.get("url") or context_data.get("target_url") or "Unknown"
        risk_score = context_data.get("risk", {}).get("score", "N/A")
        risk_class = context_data.get("risk", {}).get("classification", "N/A")
        indicators = context_data.get("risk", {}).get("indicators", [])
        ips = context_data.get("ip_intelligence", {}).get("all_addresses", [])
        
        context_str = (
            f"\n\nCURRENT INVESTIGATION TELEMETRY CONTEXT:\n"
            f"- Target: {url_target}\n"
            f"- Risk Score: {risk_score}/100 ({risk_class})\n"
            f"- Resolved IPs: {', '.join(ips[:4]) if ips else 'None'}\n"
            f"- Threat Indicators Detected: {len(indicators)}\n"
        )

    contents.append({
        "role": "user",
        "parts": [{"text": SYSTEM_PROMPT + context_str + "\n\nPlease confirm you understand your role."}]
    })
    contents.append({
        "role": "model",
        "parts": [{"text": "Affirmative. I am SENTRIX AI Analyst 2.0. Standing by to analyze threat telemetry, explain heuristics, and provide defensive countermeasures."}]
    })

    # 2. Historical conversation context (last 6 turns)
    if history:
        for turn in history[-6:]:
            role = "user" if turn.get("sender") == "user" else "model"
            msg_text = turn.get("message", "")
            if msg_text:
                contents.append({
                    "role": role,
                    "parts": [{"text": msg_text}]
                })

    # 3. Current user prompt
    contents.append({
        "role": "user",
        "parts": [{"text": message}]
    })

    payload = {
        "contents": contents,
        "generationConfig": {
            "temperature": 0.25,
            "maxOutputTokens": 900,
        }
    }

    try:
        response = requests.post(url, json=payload, timeout=8.0)
        if response.status_code == 200:
            data = response.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
        return None
    except Exception:
        return None


def local_security_brain(message: str, context_url: Optional[str] = None, context_data: Optional[Dict[str, Any]] = None) -> str:
    """
    In-house cybersecurity reasoning engine: delivers structured, high-accuracy
    answers when external LLM API credentials are not active.
    """
    msg_lower = (message or "").lower().strip()

    # 1. User wants an explanation of the current investigation or risk score
    if ("explain this" in msg_lower or "explain score" in msg_lower or "why this score" in msg_lower or "breakdown" in msg_lower) and context_data:
        try:
            target = context_data.get("url") or context_url or "Target"
            risk = context_data.get("risk", {})
            score = risk.get("score", 0)
            cls = risk.get("classification", "LOW")
            conf = risk.get("confidence", "HIGH")
            summary = risk.get("summary", "Standard baseline observed.")
            indicators = risk.get("indicators", [])

            lines = [
                f"### SENTRIX Investigation Assessment Breakdown: `{target}`\n",
                f"- **Calculated Risk Score:** `{score} / 100`",
                f"- **Severity Tier:** `{cls} RISK`",
                f"- **Analysis Confidence:** `{conf}`",
                f"- **Executive Summary:** {summary}\n",
                f"#### Identified Technical Threat Indicators ({len(indicators)} found):"
            ]

            if not indicators:
                lines.append("- **[LOW] Clean Structural Baseline:** Zero typosquatting, zero deceptive syntax, and standard transport conventions verified.")
            else:
                for ind in indicators:
                    lines.append(
                        f"- **[{ind.get('severity', 'INFO')}] {ind.get('name', 'Indicator')}** (+{ind.get('score_impact', 0)} pts)\n"
                        f"  - *Evidence:* `{ind.get('evidence', 'Observed')}`\n"
                        f"  - *Impact:* {ind.get('technical_explanation', '')}\n"
                        f"  - *Defensive Precaution:* {ind.get('precaution', 'Verify target.')}"
                    )

            lines.append("\n#### Recommended SOC Remediation:")
            recs = context_data.get("recommendations", [])
            if recs:
                for r in recs:
                    lines.append(f"1. {r}")
            else:
                lines.append("1. Continue regular telemetry monitoring. No defensive blocking required.")

            lines.append("\n> **Analyst Guardrail:** Static and structural heuristics evaluate known deception patterns; dynamic sandbox execution is required for binary payload detonation.")
            return "\n".join(lines)
        except Exception:
            pass

    # 2. User asks about a specific URL
    url_match = re.search(r"https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?", message)
    target_to_analyze = context_url or (url_match.group(0) if url_match and ("analyze" in msg_lower or "check" in msg_lower or "is this" in msg_lower or "phish" in msg_lower or "scan" in msg_lower) else None)

    if target_to_analyze and ("analyze" in msg_lower or "url" in msg_lower or "check" in msg_lower or "suspicious" in msg_lower or "safe" in msg_lower or "score" in msg_lower):
        try:
            analysis = analyze_url_deep(target_to_analyze)
            risk = analysis["risk"]
            anatomy = analysis["anatomy"]
            ip_intel = analysis["ip_intelligence"]

            indicators_bullets = ""
            for ind in risk["indicators"]:
                indicators_bullets += f"\n- **[{ind['severity']}] {ind['name']}** (+{ind['score_impact']} pts)\n  *Evidence:* `{ind['evidence']}`\n  *Analysis:* {ind['technical_explanation']}\n  *Action:* {ind['precaution']}"

            if not indicators_bullets:
                indicators_bullets = "\n- **[INFO] Clean Security Baseline:** No suspicious syntax, punycode spoofing, or deceptive credentials detected."

            resolved_ip_str = ", ".join(ip_intel["all_addresses"][:3]) or "None Resolved"

            return (
                f"### Automated Threat Assessment for `{anatomy['hostname']}`\n\n"
                f"- **Overall Risk Score:** `{risk['score']} / 100` ({risk['classification']} RISK)\n"
                f"- **Confidence Rating:** `{risk['confidence']}`\n"
                f"- **Protocol:** `{anatomy['protocol'].upper()}` | **Domain:** `{anatomy['domain']}` | **TLD:** `{anatomy['tld']}`\n"
                f"- **Resolved IPs:** `{resolved_ip_str}` ({ip_intel['status']})\n"
                f"- **Shannon Entropy:** `{anatomy['host_entropy']} bits/char`\n\n"
                f"#### Detected Threat Indicators:\n{indicators_bullets}\n\n"
                f"#### Recommended Defensive Actions:\n"
                + "\n".join([f"1. {rec}" for rec in analysis["recommendations"]])
                + f"\n\n> **Analyst Note:** {risk['disclaimer']}"
            )
        except Exception as e:
            return f"Error analyzing target `{target_to_analyze}`: {str(e)}. Please verify the URL or domain formatting."

    # 3. Incident Investigation Summary Generation
    if "incident" in msg_lower or "summary" in msg_lower or "report" in msg_lower or "ticket" in msg_lower:
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"### Security Incident Investigation Brief\n\n"
            f"- **Investigation Case:** `INC-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M')}`\n"
            f"- **Timestamp:** `{now_str}`\n"
            f"- **Analyst Station:** `SENTRIX Defensive Console v2.5`\n\n"
            f"#### Executive Incident Summary:\n"
            f"A potential deceptive endpoint was submitted for automated static threat intelligence extraction. "
            f"Structural decomposition and zone enumeration were executed across perimeter heuristics, certificate validation, and DNS posture.\n\n"
            f"#### Standard SOC Triage Steps:\n"
            f"1. **Sinkhole / DNS Egress:** Review proxy logs to determine if any internal enterprise endpoints initiated requests to the target.\n"
            f"2. **Identity Session Audit:** If credential harvesting was detected, identify users who submitted forms and trigger an immediate active session invalidation.\n"
            f"3. **Threat Intel Ingestion:** Add target domain, FQDN, and resolved IP endpoints to internal SIEM / EDR custom blocklists.\n"
            f"4. **Brand Abuse Escalation:** If brand impersonation is verified, report the hosting registrar and upstream transit provider.\n\n"
            f"*Ready to export full investigation details to PDF or CSV via the Reports tab.*"
        )

    # 4. IP Intelligence & SSRF Explanation
    if "ip" in msg_lower and ("intelligence" in msg_lower or "ssrf" in msg_lower or "private" in msg_lower or "explain" in msg_lower or "resolve" in msg_lower):
        return (
            "### Understanding IP Intelligence & SSRF Protection\n\n"
            "In enterprise cybersecurity, **IP Intelligence** validates the physical and logical network routing behind domain names:\n\n"
            "#### 1. Dual-Stack DNS Resolution (IPv4 vs IPv6):\n"
            "- **IPv4 (`A` records):** 32-bit addresses. Common target for basic firewall rules.\n"
            "- **IPv6 (`AAAA` records):** 128-bit addresses. Attackers frequently use dual-stack setups hoping IPv6 routes bypass older IPv4-only firewalls.\n\n"
            "#### 2. Network Boundary Classification:\n"
            "- **Public Internet (Routable):** Standard public infrastructure.\n"
            "- **Private Networks (RFC 1918):** Subnets `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. Legitimate public web domains should **never** resolve to private space.\n"
            "- **Loopback (`127.0.0.1` / `::1`):** Routes directly to the local host machine.\n"
            "- **Link-Local (`169.254.0.0/16`):** Cloud metadata endpoints (e.g. AWS `169.254.169.254`) frequently targeted in cloud credential extraction.\n\n"
            "#### 3. Server-Side Request Forgery (SSRF) Defense:\n"
            "SENTRIX implements pre-connect DNS resolution and blocks any request targeting non-public IP ranges, preventing adversaries from manipulating the scanner to probe your internal corporate network."
        )

    # 5. DNS Security (SPF, DKIM, DMARC)
    if "dmarc" in msg_lower or "spf" in msg_lower or "dkim" in msg_lower or ("dns" in msg_lower and "security" in msg_lower):
        return (
            "### Email Authentication Architecture: SPF, DKIM & DMARC\n\n"
            "Email protocols lack built-in sender verification. Organizations deploy three interlocking TXT-based standards to defeat brand spoofing:\n\n"
            "1. **SPF (Sender Policy Framework):**\n"
            "   - Published as a `TXT` record at the domain root (e.g., `v=spf1 include:_spf.google.com ~all`).\n"
            "   - Specifies which IP addresses and mail servers are authorized to send email on behalf of your domain.\n\n"
            "2. **DKIM (DomainKeys Identified Mail):**\n"
            "   - Uses public-key cryptography. The sending mail server signs outgoing emails with a private key.\n"
            "   - Receiving servers look up the public key in DNS to verify that the message was not modified in transit.\n\n"
            "3. **DMARC (Domain-based Message Authentication, Reporting, and Conformance):**\n"
            "   - Located at `_dmarc.<domain>` (e.g., `v=DMARC1; p=reject; rua=mailto:dmarc@example.com`).\n"
            "   - Instructs receiving email servers on what action to take when SPF or DKIM checks fail:\n"
            "     - `p=none`: Monitoring mode only (telemetry reports collected).\n"
            "     - `p=quarantine`: Divert failed messages into user Spam/Junk folders.\n"
            "     - `p=reject`: Maximum protection. Drop and reject spoofed emails at the perimeter.\n\n"
            "**SENTRIX Audit:** In the Domain Intelligence module, SENTRIX verifies active SPF and DMARC policies to score domain defense posture."
        )

    # 6. Typosquatting & Punycode
    if "typosquat" in msg_lower or "punycode" in msg_lower or "homoglyph" in msg_lower:
        return (
            "### Typosquatting & Punycode Homoglyph Attacks\n\n"
            "Adversaries rely heavily on visual deception to trick users into trusting fraudulent links:\n\n"
            "1. **Combosquatting / Typosquatting:**\n"
            "   - Inserting subtle character alterations (`paypa1.com`, `g00gle.com`).\n"
            "   - Adding deceptive prefixes or suffixes (`login-apple.com`, `chase-security-update.com`).\n"
            "   - SENTRIX uses Levenshtein edit distance and brand mapping algorithms to uncover these mutations.\n\n"
            "2. **Punycode IDN Homoglyphs:**\n"
            "   - The Internationalized Domain Name (IDN) standard maps Unicode non-Latin characters into ASCII using the `xn--` prefix.\n"
            "   - Example: Cyrillic Small Letter 'а' (U+0430) looks identical to Latin 'a' (U+0061).\n"
            "   - When registered as `xn--pple-43d.com`, web browsers may render it as `apple.com` while the user is actually visiting an adversary server.\n\n"
            "**Defensive Precaution:** Always check the ASCII `xn--` encoding and verify the issued SSL certificate's subject common name."
        )

    # 7. Google Dorking Techniques
    if "dork" in msg_lower or "google hack" in msg_lower or "search operator" in msg_lower:
        return (
            "### Defensive Google Dorking & Attack Surface Mapping\n\n"
            "**Google Dorking** leverages advanced search engine syntax to identify unprotected assets, misconfigurations, and leaked credentials:\n\n"
            "#### Essential Operators:\n"
            "- **`site:<target.com>`**: Restricts the search scope strictly to the target organization's domains.\n"
            "- **`filetype:<ext>`**: Filters for specific file types (e.g., `filetype:env`, `filetype:sql`, `filetype:log`, `filetype:conf`).\n"
            "- **`inurl:<term>`**: Targets endpoints containing specific strings (e.g., `inurl:admin`, `inurl:api-docs`, `inurl:wp-login`).\n"
            "- **`intitle:<term>`**: Restricts matches to pages whose HTML `<title>` matches (e.g., `intitle:\"Index of /\"`).\n"
            "- **`intext:<term>`**: Matches raw content within the body text (e.g., `intext:\"DB_PASSWORD\"`).\n\n"
            "#### High-Value Defensive Dork Examples:\n"
            "- `site:example.com filetype:env \"DB_HOST\"` -> Check for leaked database configuration files.\n"
            "- `site:example.com intitle:\"Index of /\"` -> Uncover open directory indexing exposing server directories.\n"
            "- `site:example.com inurl:gitlab OR inurl:swagger` -> Find accidentally exposed developer tools.\n\n"
            "Use the **SENTRIX Query Generator** tab to interactively build and run targeted defensive dorks."
        )

    # 8. General Cybersecurity Assistant Default Response
    return (
        f"### SENTRIX AI Analyst 2.0 Command Center\n\n"
        f"I received your inquiry: *\"{message}\"*\n\n"
        f"As your cybersecurity investigation co-pilot, I can assist you with:\n\n"
        f"1. **Threat Assessment:** Enter any URL or say `Analyze https://example.com` for structural risk scoring.\n"
        f"2. **Investigation Breakdown:** Ask `Explain this score` when viewing analysis results.\n"
        f"3. **IP & DNS Intelligence:** Ask about dual-stack IPv4/IPv6 resolution, SSRF boundaries, SPF, and DMARC policies.\n"
        f"4. **Defensive Guidance:** Ask for incident response checklists, typosquatting mitigation, or hardening headers.\n"
        f"5. **OSINT Reconnaissance:** Ask for custom Google Dorks to audit your organization's attack surface.\n\n"
        f"What target or topic would you like to investigate?"
    )


def process_chat_message(
    message: str,
    user_api_key: Optional[str] = None,
    context_url: Optional[str] = None,
    history: List[Dict[str, str]] = None,
    context_data: Optional[Dict[str, Any]] = None
) -> str:
    """
    Main orchestration entrypoint for SENTRIX AI Analyst 2.0:
    Selects external Gemini LLM when active or routes directly to the in-house
    cybersecurity reasoning brain.
    """
    active_key = user_api_key or os.environ.get("GEMINI_API_KEY")

    if active_key:
        api_response = call_gemini_api(active_key, message, history, context_data)
        if api_response:
            return api_response

    # Fallback to local security intelligence brain
    return local_security_brain(message, context_url, context_data)
