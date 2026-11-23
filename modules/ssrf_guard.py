"""
SENTRIX SSRF Guard & Safe HTTP Client
Protects against Server-Side Request Forgery, DNS Rebinding, loopback/private IP scanning.
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple, Optional, Dict, Any
import requests

# Blocked IP Networks (RFC 1918, RFC 3927, Loopback, Link-Local, Multicast, CGNAT, etc.)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private-Use
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (CGNAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private-Use
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (Documentation)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private-Use
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (Documentation)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (Documentation)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

FORBIDDEN_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "169.254.169.254", "instance-data",
    "kubernetes.default", "kubernetes.default.svc"
}

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_TIMEOUT = 4.0  # seconds
MAX_RESPONSE_SIZE = 512 * 1024  # 512 KB
USER_AGENT = "SENTRIX-Security-Scanner/2.4 (Defensive Research; +https://sentrix.security)"


def is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address string belongs to any private, loopback, or reserved subnet.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return True, f"Loopback address ({ip}) is blocked."
    if ip.is_private:
        return True, f"Private/Internal IP ({ip}) is blocked (SSRF Protection)."
    if ip.is_link_local:
        return True, f"Link-local IP ({ip}) is blocked."
    if ip.is_multicast:
        return True, f"Multicast IP ({ip}) is blocked."
    if ip.is_reserved:
        return True, f"Reserved IP ({ip}) is blocked."

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True, f"IP ({ip}) falls within restricted network {net} (SSRF Protection)."

    return False, "Public routable IP."


def validate_hostname_safe(hostname: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates a hostname by resolving all A / AAAA records and checking that
    none point to loopback, link-local, or private IP addresses.
    Returns: (is_safe, message, resolved_ip)
    """
    clean_host = hostname.strip().lower()
    if not clean_host:
        return False, "Empty hostname provided.", None

    if clean_host in FORBIDDEN_HOSTNAMES or clean_host.endswith(".local") or clean_host.endswith(".internal"):
        return False, f"Hostname '{clean_host}' is blocked for SSRF protection.", None

    # Check if host is already an IP address
    try:
        ip = ipaddress.ip_address(clean_host)
        blocked, reason = is_ip_blocked(str(ip))
        if blocked:
            return False, reason, None
        return True, "Valid public IP.", str(ip)
    except ValueError:
        pass  # Not an IP literal, proceed to resolve

    # Resolve hostname via standard socket
    try:
        addrinfo = socket.getaddrinfo(clean_host, None)
        resolved_ips = []
        for entry in addrinfo:
            ip_candidate = entry[4][0]
            resolved_ips.append(ip_candidate)
            blocked, reason = is_ip_blocked(ip_candidate)
            if blocked:
                return False, f"Hostname '{clean_host}' resolves to restricted IP {ip_candidate}: {reason}", None
        
        primary_ip = resolved_ips[0] if resolved_ips else None
        return True, f"Hostname '{clean_host}' verified as public.", primary_ip
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{clean_host}': {str(e)}", None
    except Exception as e:
        return False, f"Resolution error for '{clean_host}': {str(e)}", None


def sanitize_and_validate_url(raw_url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Sanitizes URL string, checks scheme and hostname safety against SSRF.
    Returns (is_valid, error_or_success_message, normalized_url)
    """
    if not raw_url:
        return False, "URL cannot be empty.", None

    cleaned = raw_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        # Default prepend https:// for analysis if missing scheme
        cleaned = "https://" + cleaned

    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except Exception as e:
        return False, f"Failed to parse URL: {str(e)}", None

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname.", None

    safe, msg, resolved_ip = validate_hostname_safe(hostname)
    if not safe:
        return False, msg, None

    normalized = urllib.parse.urlunsplit(parsed)
    return True, "URL is valid and public.", normalized


def safe_http_head(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Performs a safe HEAD request (with GET stream fallback) and SSRF verification on every redirect hop.
    """
    is_valid, msg, normalized_url = sanitize_and_validate_url(url)
    if not is_valid:
        return {"success": False, "error": msg, "headers": {}, "status_code": None}

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*"
    }

    def _validate_all_hops(resp):
        for h in getattr(resp, "history", []):
            host = urllib.parse.urlsplit(h.url).hostname
            if host:
                safe, reason, _ = validate_hostname_safe(host)
                if not safe:
                    return False, f"SSRF blocked intermediary hop ({host}): {reason}"
        final_host = urllib.parse.urlsplit(resp.url).hostname
        if final_host:
            safe, reason, _ = validate_hostname_safe(final_host)
            if not safe:
                return False, f"SSRF blocked destination ({final_host}): {reason}"
        return True, None

    try:
        resp = requests.head(
            normalized_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=True
        )
        safe_hops, hop_err = _validate_all_hops(resp)
        if not safe_hops:
            return {"success": False, "error": hop_err, "headers": {}, "status_code": 403}

        # If server returns 405 Method Not Allowed on HEAD, attempt stream GET for headers only
        if resp.status_code == 405:
            resp = requests.get(
                normalized_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
                verify=True
            )
            safe_hops, hop_err = _validate_all_hops(resp)
            if not safe_hops:
                return {"success": False, "error": hop_err, "headers": {}, "status_code": 403}

        return {
            "success": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "url": resp.url
        }
    except requests.exceptions.SSLError as e:
        # Retry with SSL verification skipped only for header inspection, with warning
        try:
            resp = requests.head(
                normalized_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False
            )
            safe_hops, hop_err = _validate_all_hops(resp)
            if not safe_hops:
                return {"success": False, "error": hop_err, "headers": {}, "status_code": 403}

            return {
                "success": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "url": resp.url,
                "ssl_warning": f"SSL verification failed: {str(e)}"
            }
        except Exception as retry_e:
            return {"success": False, "error": f"Connection error: {str(retry_e)}", "headers": {}, "status_code": None}
    except Exception as e:
        return {"success": False, "error": str(e), "headers": {}, "status_code": None}
