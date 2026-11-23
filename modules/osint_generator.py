"""
SENTRIX OSINT & Google Dork Query Generator
Generates structured, categorized defensive intelligence search queries for security researchers,
complete with operator definitions, rationale, and export facilities.
"""

from typing import List, Dict, Any
import urllib.parse
import csv
import io


OSINT_CATEGORIES = {
    "files": {
        "title": "Publicly Indexed Files",
        "description": "Uncover exposed documents, backups, spreadsheets, and configuration scripts indexed by search engines.",
        "icon": "file-text",
        "templates": [
            {
                "name": "Exposed Sensitive Documents",
                "pattern": 'site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx "confidential" OR "internal use only"',
                "explanation": "Identifies proprietary documents containing confidentiality markings publicly accessible on the domain."
            },
            {
                "name": "Database Dumps & SQL Files",
                "pattern": 'site:{domain} filetype:sql OR filetype:dump OR filetype:db "INSERT INTO" OR "CREATE TABLE"',
                "explanation": "Locates accidental backups or database migration scripts that could reveal internal schema or credentials."
            },
            {
                "name": "Configuration & Environment Files",
                "pattern": 'site:{domain} filetype:env OR filetype:ini OR filetype:conf OR filetype:yaml "DB_PASSWORD" OR "api_key"',
                "explanation": "Searches for unmasked configuration files that frequently leak API secrets, database passwords, and environment variables."
            },
            {
                "name": "Backup Archives",
                "pattern": 'site:{domain} filetype:bak OR filetype:old OR filetype:zip OR filetype:tar "backup"',
                "explanation": "Detects legacy or backup zip/tar files left unattended in publicly accessible web root directories."
            },
            {
                "name": "Server & Debug Log Files",
                "pattern": 'site:{domain} filetype:log "error" OR "exception" OR "debug" OR "warning"',
                "explanation": "Finds exposed application and server log files that may reveal stack traces, system paths, or IP addresses."
            }
        ]
    },
    "login": {
        "title": "Login & Authentication Portals",
        "description": "Map internal enterprise access gates, single sign-on points, and administrative panels.",
        "icon": "key-round",
        "templates": [
            {
                "name": "Administrative Dashboards",
                "pattern": 'site:{domain} inurl:admin OR inurl:login OR inurl:portal OR inurl:dashboard',
                "explanation": "Surfaces management consoles and sign-in interfaces that should ideally be protected behind VPNs or IP allowlists."
            },
            {
                "name": "SSO & Identity Provider Endpoints",
                "pattern": 'site:{domain} inurl:sso OR inurl:oauth OR inurl:saml OR inurl:auth',
                "explanation": "Discovers corporate identity providers and single sign-on endpoints used across corporate web properties."
            },
            {
                "name": "Password Reset & Recovery Pages",
                "pattern": 'site:{domain} inurl:forgot-password OR inurl:reset-password OR inurl:recover',
                "explanation": "Identifies credential recovery pages to verify whether rate-limiting and captcha controls are implemented."
            },
            {
                "name": "Webmail & Exchange Interfaces",
                "pattern": 'site:{domain} inurl:webmail OR inurl:owa OR inurl:roundcube OR inurl:mail',
                "explanation": "Detects web-based email portals such as Outlook Web Access or Roundcube for exposure auditing."
            }
        ]
    },
    "directories": {
        "title": "Publicly Indexed Directories",
        "description": "Find open directory listings and unindexed folders left with directory indexing enabled.",
        "icon": "folder-search",
        "templates": [
            {
                "name": "Apache / Nginx Directory Listings",
                "pattern": 'site:{domain} intitle:"Index of /" OR intitle:"Index of /uploads"',
                "explanation": "Detects servers with 'Options +Indexes' misconfigured, exposing all files inside server directories."
            },
            {
                "name": "Common Exposed Asset Folders",
                "pattern": 'site:{domain} inurl:/uploads/ OR inurl:/files/ OR inurl:/backup/ OR inurl:/download/',
                "explanation": "Scans for open upload directories where sensitive user-uploaded content or files might reside."
            },
            {
                "name": "Version Control Repositories (.git)",
                "pattern": 'site:{domain} inurl:.git OR inurl:.svn OR inurl:.hg',
                "explanation": "Checks if `.git` or version control metadata directories were accidentally deployed to production web roots."
            }
        ]
    },
    "subdomains": {
        "title": "Subdomain Research",
        "description": "Discover staging environments, developer branches, internal tools, and microservice hosts.",
        "icon": "network",
        "templates": [
            {
                "name": "All Indexed Subdomains",
                "pattern": 'site:*.{domain} -site:www.{domain}',
                "explanation": "Negates the main `www` host to discover all other subdomains currently indexed by Google."
            },
            {
                "name": "Staging & Development Environments",
                "pattern": 'site:{domain} inurl:dev OR inurl:staging OR inurl:test OR inurl:qa OR inurl:beta',
                "explanation": "Locates non-production environments that may have relaxed security controls or unpatched vulnerabilities."
            },
            {
                "name": "API & Microservice Hosts",
                "pattern": 'site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql OR inurl:rest',
                "explanation": "Maps public-facing REST or GraphQL API endpoints to assess authentication requirements."
            },
            {
                "name": "Internal & VPN Gateways",
                "pattern": 'site:{domain} inurl:vpn OR inurl:remote OR inurl:intranet OR inurl:corp',
                "explanation": "Detects remote access gateways (Cisco AnyConnect, Citrix, Fortinet, GlobalProtect) on company subdomains."
            }
        ]
    },
    "documentation": {
        "title": "Public Documentation & Manuals",
        "description": "Locate system architecture guides, employee onboarding manuals, and internal documentation.",
        "icon": "book-open",
        "templates": [
            {
                "name": "Internal User Guides & Manuals",
                "pattern": 'site:{domain} filetype:pdf "user manual" OR "employee handbook" OR "standard operating procedure"',
                "explanation": "Finds instructional guides that detail internal operational procedures, tech stacks, or contact hierarchies."
            },
            {
                "name": "Swagger & API Specs",
                "pattern": 'site:{domain} inurl:swagger OR inurl:api-docs OR inurl:"redoc" OR intitle:"Swagger UI"',
                "explanation": "Identifies interactive Swagger/OpenAPI documentation portals describing endpoint parameters and authorization models."
            },
            {
                "name": "Architecture & Topology Whitepapers",
                "pattern": 'site:{domain} filetype:pdf "network diagram" OR "system architecture" OR "data flow diagram"',
                "explanation": "Uncovers technical infrastructure diagrams often published in academic or partnership whitepapers."
            }
        ]
    },
    "technology": {
        "title": "Technology Identification",
        "description": "Identify content management systems, web frameworks, and software stacks in use.",
        "icon": "cpu",
        "templates": [
            {
                "name": "WordPress Footprints",
                "pattern": 'site:{domain} inurl:wp-content OR inurl:wp-includes OR inurl:xmlrpc.php',
                "explanation": "Discovers WordPress installations, active plugins, theme directories, and XML-RPC interfaces."
            },
            {
                "name": "Drupal & Joomla Footprints",
                "pattern": 'site:{domain} inurl:node OR inurl:administrator/ OR inurl:option=com_',
                "explanation": "Reveals Drupal or Joomla CMS endpoints for target version and patch level auditing."
            },
            {
                "name": "PHP & Server Footprints",
                "pattern": 'site:{domain} filetype:php inurl:phpinfo OR inurl:test.php OR inurl:info.php',
                "explanation": "Checks for test scripts or `phpinfo()` files that disclose complete server module configurations."
            }
        ]
    },
    "config": {
        "title": "Configuration & Error Leaks",
        "description": "Find exposed database connection strings, stack traces, and unhandled exception dumps.",
        "icon": "shield-alert",
        "templates": [
            {
                "name": "SQL Syntax Error Dumps",
                "pattern": 'site:{domain} "SQL syntax near" OR "syntax error has occurred" OR "ORA-00933"',
                "explanation": "Finds indexed pages containing database error traces indicating potential SQL injection vectors."
            },
            {
                "name": "Django / Flask Debug Pages",
                "pattern": 'site:{domain} "DisallowedHost at" OR "OperationalError at" OR "Werkzeug Debugger"',
                "explanation": "Detects Python frameworks running in production with `DEBUG=True` mode active, exposing interactive debug consoles."
            },
            {
                "name": "AWS & Cloud S3 Buckets",
                "pattern": 'site:{domain} "s3.amazonaws.com" OR "blob.core.windows.net" OR "storage.googleapis.com"',
                "explanation": "Identifies cloud object storage buckets referenced in public pages to audit access permissions."
            }
        ]
    },
    "contact": {
        "title": "Public Contact & People Research",
        "description": "Discover employee email address formats, organizational directories, and communication channels.",
        "icon": "users",
        "templates": [
            {
                "name": "Email Address Scraping Patterns",
                "pattern": 'site:{domain} "email" OR "contact us" OR "mailto:" "@ {domain}"',
                "explanation": "Gathers corporate email syntax and public address listings to understand naming conventions."
            },
            {
                "name": "Staff Directory & Executive Team",
                "pattern": 'site:{domain} inurl:team OR inurl:staff OR inurl:faculty OR inurl:leadership',
                "explanation": "Maps organizational hierarchy and personnel for authorized social engineering resistance testing."
            },
            {
                "name": "Customer Support & Ticketing Systems",
                "pattern": 'site:{domain} inurl:helpdesk OR inurl:jira OR inurl:zendesk OR inurl:freshdesk',
                "explanation": "Discovers customer support knowledgebases and ticketing portals associated with the company."
            }
        ]
    }
}


def generate_dorks_for_domain(domain: str, category: str = "all") -> Dict[str, Any]:
    """
    Generates OSINT queries for a given domain, filtered by category or across all categories.
    """
    clean_domain = domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://")[1].split("/")[0].split(":")[0]
    elif "/" in clean_domain:
        clean_domain = clean_domain.split("/")[0].split(":")[0]

    if not clean_domain:
        return {"success": False, "error": "Invalid domain name."}

    results = []
    cats_to_process = [category] if category in OSINT_CATEGORIES else list(OSINT_CATEGORIES.keys())

    for cat_key in cats_to_process:
        cat_info = OSINT_CATEGORIES[cat_key]
        queries_list = []
        for tmpl in cat_info["templates"]:
            rendered_query = tmpl["pattern"].replace("{domain}", clean_domain)
            google_url = f"https://www.google.com/search?q={urllib.parse.quote(rendered_query)}"
            queries_list.append({
                "name": tmpl["name"],
                "query": rendered_query,
                "explanation": tmpl["explanation"],
                "google_search_url": google_url
            })
        
        results.append({
            "category_id": cat_key,
            "category_title": cat_info["title"],
            "category_description": cat_info["description"],
            "icon": cat_info["icon"],
            "queries": queries_list
        })

    total_queries = sum(len(c["queries"]) for c in results)

    return {
        "success": True,
        "domain": clean_domain,
        "total_queries": total_queries,
        "categories": results
    }


def export_queries_txt(queries_data: Dict[str, Any]) -> str:
    """
    Formats generated OSINT queries into a structured TXT research playbook.
    """
    output = []
    output.append("=" * 70)
    output.append(f"SENTRIX OSINT & GOOGLE DORK INTELLIGENCE REPORT")
    output.append(f"Target Domain: {queries_data.get('domain', 'Unknown')}")
    output.append(f"Total Queries: {queries_data.get('total_queries', 0)}")
    output.append("Defensive Security Research Purpose Only")
    output.append("=" * 70 + "\n")

    for cat in queries_data.get("categories", []):
        output.append(f"[{cat['category_title'].upper()}]")
        output.append(f"Description: {cat['category_description']}\n")
        for q in cat["queries"]:
            output.append(f"  * {q['name']}")
            output.append(f"    Query: {q['query']}")
            output.append(f"    Rationale: {q['explanation']}")
            output.append(f"    URL: {q['google_search_url']}\n")
        output.append("-" * 70 + "\n")

    return "\n".join(output)


def export_queries_csv(queries_data: Dict[str, Any]) -> str:
    """
    Formats generated OSINT queries into CSV format.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Target Domain", "Category", "Query Name", "Dork Query", "Technical Explanation", "Google Search URL"])

    domain = queries_data.get("domain", "")
    for cat in queries_data.get("categories", []):
        cat_title = cat["category_title"]
        for q in cat["queries"]:
            writer.writerow([
                domain,
                cat_title,
                q["name"],
                q["query"],
                q["explanation"],
                q["google_search_url"]
            ])

    return buf.getvalue()
