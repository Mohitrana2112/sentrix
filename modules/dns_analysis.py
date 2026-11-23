"""
SENTRIX DNS Analysis Module
Leverages dnspython to query A, AAAA, MX, NS, TXT, CNAME, and SOA records
with TTL caching metrics, reverse PTR lookups, and security record inspection.
"""

import time
import socket
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.reversename
import dns.exception


def query_dns_records(domain: str) -> Dict[str, Any]:
    """
    Performs comprehensive DNS enumeration for a given domain name.
    """
    clean_domain = domain.strip().lower()
    # Strip protocols and paths if a full URL was accidentally passed
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://")[1].split("/")[0].split(":")[0]
    elif "/" in clean_domain:
        clean_domain = clean_domain.split("/")[0].split(":")[0]

    results: Dict[str, Any] = {
        "domain": clean_domain,
        "query_time_ms": 0,
        "records": {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
            "SOA": []
        },
        "security_features": {
            "has_spf": False,
            "has_dmarc": False,
            "dmarc_record": None,
            "spf_record": None,
            "dnssec_present": False
        },
        "errors": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 4.0

    start_time = time.time()

    # Query Record Types
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(clean_domain, rtype)
            for rdata in answers:
                record_entry = {
                    "value": str(rdata).strip('"'),
                    "ttl": answers.ttl
                }
                if rtype == "MX":
                    record_entry["preference"] = getattr(rdata, "preference", 0)
                    record_entry["exchange"] = str(getattr(rdata, "exchange", "")).rstrip(".")
                elif rtype == "SOA":
                    record_entry["mname"] = str(getattr(rdata, "mname", "")).rstrip(".")
                    record_entry["rname"] = str(getattr(rdata, "rname", "")).rstrip(".")
                    record_entry["serial"] = getattr(rdata, "serial", 0)

                results["records"][rtype].append(record_entry)

                # Check SPF in TXT records
                if rtype == "TXT" and "v=spf1" in record_entry["value"].lower():
                    results["security_features"]["has_spf"] = True
                    results["security_features"]["spf_record"] = record_entry["value"]

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.LifetimeTimeout:
            results["errors"].append(f"Timeout querying {rtype} records.")
        except Exception as e:
            results["errors"].append(f"Error querying {rtype}: {str(e)}")

    # Check for DMARC specifically at _dmarc.<domain>
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{clean_domain}", "TXT")
        for d_data in dmarc_answers:
            val = str(d_data).strip('"')
            if "v=dmarc1" in val.lower():
                results["security_features"]["has_dmarc"] = True
                results["security_features"]["dmarc_record"] = val
    except Exception:
        results["security_features"]["has_dmarc"] = False

    # PTR reverse resolution for primary A record
    if results["records"]["A"]:
        primary_ip = results["records"]["A"][0]["value"]
        try:
            rev_name = dns.reversename.from_address(primary_ip)
            ptr_answer = resolver.resolve(rev_name, "PTR")
            results["records"]["PTR"] = [str(r).rstrip(".") for r in ptr_answer]
        except Exception:
            results["records"]["PTR"] = []
    else:
        results["records"]["PTR"] = []

    elapsed = round((time.time() - start_time) * 1000, 2)
    results["query_time_ms"] = elapsed

    # Summary analysis
    results["total_records_found"] = sum(len(records) for records in results["records"].values())
    return results
