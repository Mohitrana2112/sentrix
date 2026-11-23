"""
SENTRIX Redirect Analysis Module
Safely traces HTTP redirect chains hop-by-hop with SSRF guard enforcement on every hop,
protocol transition analysis, status code tracking, and graph node mapping.
"""

import time
import urllib.parse
from typing import Dict, Any, List
import requests
from modules.ssrf_guard import sanitize_and_validate_url, validate_hostname_safe, USER_AGENT

MAX_REDIRECT_HOPS = 7
HOP_TIMEOUT = 3.5


def trace_redirect_chain(start_url: str) -> Dict[str, Any]:
    """
    Traces the journey of a URL through all HTTP redirects safely,
    verifying each intermediary destination against SSRF rules.
    """
    valid, msg, current_url = sanitize_and_validate_url(start_url)
    if not valid:
        return {
            "success": False,
            "error": msg,
            "original_url": start_url,
            "hops": [],
            "hop_count": 0,
            "final_url": None
        }

    hops: List[Dict[str, Any]] = []
    visited_urls = set()
    final_destination = current_url
    has_downgrade = False
    has_cross_domain = False

    orig_parsed = urllib.parse.urlsplit(current_url)
    origin_domain = orig_parsed.hostname or ""

    for step in range(1, MAX_REDIRECT_HOPS + 1):
        if current_url in visited_urls:
            hops.append({
                "step": step,
                "url": current_url,
                "status_code": "LOOP",
                "reason": "Circular redirect loop detected!",
                "latency_ms": 0,
                "ip": None,
                "is_ssl": current_url.startswith("https://")
            })
            break

        visited_urls.add(current_url)

        # Validate next hop hostname for SSRF safety
        parsed_current = urllib.parse.urlsplit(current_url)
        host = parsed_current.hostname or ""
        safe, host_msg, resolved_ip = validate_hostname_safe(host)
        if not safe:
            hops.append({
                "step": step,
                "url": current_url,
                "status_code": "BLOCKED",
                "reason": f"Hop blocked by SSRF Guard: {host_msg}",
                "latency_ms": 0,
                "ip": None,
                "is_ssl": current_url.startswith("https://")
            })
            break

        start_time = time.time()
        try:
            resp = requests.head(
                current_url,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                timeout=HOP_TIMEOUT,
                allow_redirects=False,
                verify=False
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 1)

            status_code = resp.status_code
            redirect_target = resp.headers.get("Location")

            # Check for protocol downgrade (HTTPS -> HTTP)
            if step > 1 and hops[-1]["is_ssl"] and not current_url.startswith("https://"):
                has_downgrade = True

            # Check for cross-domain redirect
            if host != origin_domain:
                has_cross_domain = True

            hop_entry = {
                "step": step,
                "url": current_url,
                "status_code": status_code,
                "reason": resp.reason,
                "latency_ms": elapsed_ms,
                "ip": resolved_ip,
                "is_ssl": current_url.startswith("https://"),
                "next_url": None
            }

            if status_code in (301, 302, 303, 307, 308) and redirect_target:
                # Handle relative redirect locations
                resolved_target = urllib.parse.urljoin(current_url, redirect_target)
                hop_entry["next_url"] = resolved_target
                hops.append(hop_entry)
                current_url = resolved_target
                final_destination = resolved_target
            else:
                hops.append(hop_entry)
                final_destination = current_url
                break

        except requests.exceptions.Timeout:
            hops.append({
                "step": step,
                "url": current_url,
                "status_code": "TIMEOUT",
                "reason": "Connection timed out during hop resolution.",
                "latency_ms": round(HOP_TIMEOUT * 1000),
                "ip": resolved_ip,
                "is_ssl": current_url.startswith("https://")
            })
            break
        except Exception as e:
            hops.append({
                "step": step,
                "url": current_url,
                "status_code": "ERROR",
                "reason": str(e),
                "latency_ms": 0,
                "ip": resolved_ip,
                "is_ssl": current_url.startswith("https://")
            })
            break

    # Security risk assessment for the chain
    anomalies = []
    if len(hops) > 3:
        anomalies.append(f"Excessive redirect hops ({len(hops)} steps) detected.")
    if has_downgrade:
        anomalies.append("Dangerous Protocol Downgrade detected: Redirected from HTTPS to unencrypted HTTP.")
    if has_cross_domain:
        anomalies.append("Cross-domain redirection observed across different organizational hostnames.")

    return {
        "success": True,
        "original_url": start_url,
        "final_url": final_destination,
        "total_hops": len(hops),
        "hops": hops,
        "has_downgrade": has_downgrade,
        "has_cross_domain": has_cross_domain,
        "anomalies": anomalies,
    }
