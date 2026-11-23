"""
SENTRIX – Security Analysis & URL Intelligence Platform
Main Flask Application Server
"""

import os
import uuid
import datetime
import json
import ipaddress
from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, send_file, Response, make_response
)

from config import Config
from database.db import db
from database.models import (
    Investigation, URLAnalysis, DomainInvestigation,
    SavedQuery, GeneratedReport, UserSettings, ChatMessage
)
from modules.ssrf_guard import sanitize_and_validate_url
from modules.url_analysis import analyze_url_deep
from modules.domain_intelligence import investigate_domain_complete
from modules.osint_generator import (
    generate_dorks_for_domain, export_queries_txt, export_queries_csv
)
from modules.chatbot import process_chat_message
from modules.report_generator import (
    generate_pdf_report, generate_txt_report, generate_csv_report
)


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Ensure instance directory exists
    os.makedirs(app.instance_path, exist_ok=True)

    with app.app_context():
        db.create_all()
        seed_initial_data()

    # Register Context Processors
    @app.context_processor
    def inject_global_context():
        settings = UserSettings.query.first()
        return {
            "current_year": datetime.datetime.utcnow().year,
            "product_name": app.config.get("PRODUCT_NAME", "SENTRIX"),
            "product_full_name": app.config.get("PRODUCT_FULL_NAME"),
            "tagline": app.config.get("TAGLINE"),
            "app_version": app.config.get("VERSION", "2.4.0 PRO"),
            "user_settings": settings
        }

    # =========================================================================
    # CORE PAGE ROUTES
    # =========================================================================

    @app.route("/")
    @app.route("/dashboard")
    def dashboard():
        """Overview Command Center Dashboard"""
        # Calculate genuine real-time statistics from local database
        total_domains = db.session.query(DomainInvestigation).count()
        total_urls = db.session.query(URLAnalysis).count()
        suspicious_patterns = db.session.query(Investigation).filter(
            Investigation.risk_score >= 50
        ).count()
        osint_count = db.session.query(SavedQuery).count()

        # Count unique IP addresses across database records
        unique_ips = set()
        for di in DomainInvestigation.query.all():
            if di.ip_address and di.ip_address not in ("None", "", "0.0.0.0"):
                unique_ips.add(di.ip_address)
        for ua in URLAnalysis.query.all():
            if ua.hostname:
                try:
                    ipaddress.ip_address(ua.hostname)
                    unique_ips.add(ua.hostname)
                except Exception:
                    pass

        all_investigations = Investigation.query.order_by(Investigation.created_at.desc()).all()
        has_real_data = len(all_investigations) > 0

        if has_real_data:
            total_cases = len(all_investigations)
            avg_risk = round(sum(i.risk_score for i in all_investigations) / total_cases)
            low_c = sum(1 for i in all_investigations if i.risk_level == "LOW")
            med_c = sum(1 for i in all_investigations if i.risk_level == "MEDIUM")
            high_c = sum(1 for i in all_investigations if i.risk_level == "HIGH")
            crit_c = sum(1 for i in all_investigations if i.risk_level == "CRITICAL")
        else:
            total_cases = 0
            avg_risk = 0
            low_c = 0
            med_c = 0
            high_c = 0
            crit_c = 0

        risk_level_str = "CRITICAL" if avg_risk >= 75 else ("HIGH" if avg_risk >= 50 else ("MEDIUM" if avg_risk >= 25 else "LOW"))

        stats = {
            "total_domains": total_domains,
            "total_urls": total_urls,
            "total_cases": total_cases,
            "suspicious_patterns": suspicious_patterns,
            "osint_queries": osint_count,
            "unique_ips": len(unique_ips),
            "has_real_data": has_real_data
        }

        recent_investigations = all_investigations[:10]

        risk_posture = {
            "avg_score": avg_risk,
            "level": risk_level_str,
            "total_evaluated": total_cases,
            "low_count": low_c,
            "medium_count": med_c,
            "high_count": high_c,
            "critical_count": crit_c,
            "low_pct": round((low_c / max(1, total_cases)) * 100, 1) if total_cases > 0 else 0,
            "medium_pct": round((med_c / max(1, total_cases)) * 100, 1) if total_cases > 0 else 0,
            "high_pct": round((high_c / max(1, total_cases)) * 100, 1) if total_cases > 0 else 0,
            "critical_pct": round((crit_c / max(1, total_cases)) * 100, 1) if total_cases > 0 else 0,
        }

        return render_template(
            "dashboard.html",
            active_page="dashboard",
            stats=stats,
            recent_investigations=recent_investigations,
            risk_posture=risk_posture
        )

    @app.route("/url-analyzer", methods=["GET", "POST"])
    def url_analyzer():
        """Advanced URL Analyzer Workspace"""
        target_url = request.args.get("url", "").strip()
        analysis_data = None

        if target_url:
            analysis_data = analyze_url_deep(target_url)
            # Store in DB if not already present recently
            record_investigation(target_url, "url", analysis_data)

        return render_template(
            "url_analyzer.html",
            active_page="url_analyzer",
            target_url=target_url,
            initial_data=analysis_data
        )

    @app.route("/domain-intel", methods=["GET"])
    def domain_intel():
        """Domain Intelligence Center"""
        target_domain = request.args.get("domain", "").strip()
        intel_data = None

        if target_domain:
            intel_data = investigate_domain_complete(target_domain)
            record_domain_investigation(target_domain, intel_data)

        return render_template(
            "domain_intel.html",
            active_page="domain_intel",
            target_domain=target_domain,
            intel_data=intel_data
        )

    @app.route("/osint", methods=["GET"])
    @app.route("/osint-explorer", methods=["GET"])
    def osint_explorer():
        """OSINT Explorer & Google Dork Generator"""
        domain = request.args.get("domain", "example.com").strip()
        category = request.args.get("category", "all").strip()

        dork_results = None
        if domain:
            dork_results = generate_dorks_for_domain(domain, category)

        return render_template(
            "osint.html",
            active_page="osint",
            target_domain=domain,
            active_category=category,
            dork_results=dork_results
        )

    @app.route("/query-generator", methods=["GET"])
    def query_generator():
        """Interactive Query Generator Canvas"""
        target_domain = request.args.get("domain", "").strip()
        return render_template(
            "query_generator.html",
            active_page="query_generator",
            target_domain=target_domain
        )

    @app.route("/reports", methods=["GET"])
    def reports_view():
        """Investigation Reports Archive"""
        investigations = Investigation.query.order_by(
            Investigation.created_at.desc()
        ).all()
        return render_template(
            "reports.html",
            active_page="reports",
            investigations=investigations
        )

    @app.route("/settings", methods=["GET"])
    def settings_view():
        """Analyst Preferences & API Keys"""
        settings = UserSettings.query.first()
        return render_template(
            "settings.html",
            active_page="settings",
            user_settings=settings
        )

    # =========================================================================
    # API ENDPOINTS
    # =========================================================================

    @app.route("/api/analyze-url", methods=["POST"])
    def api_analyze_url():
        """AJAX endpoint for URL Analyzer"""
        data = request.get_json() or {}
        raw_url = data.get("url", "").strip()

        if not raw_url:
            return jsonify({"success": False, "error": "No URL provided."}), 400

        try:
            result = analyze_url_deep(raw_url)
            # Persist to database
            inv = record_investigation(raw_url, "url", result)
            result["investigation_uuid"] = inv.uuid if inv else None
            result["created_at"] = inv.created_at.strftime("%m-%d %H:%M") if inv and inv.created_at else "Just now"
            return jsonify(result)
        except Exception as e:
            return jsonify({"success": False, "error": f"Analysis error: {str(e)}"}), 500

    @app.route("/api/domain-intel", methods=["POST"])
    def api_domain_intel():
        """AJAX endpoint for Domain Intelligence"""
        data = request.get_json() or {}
        domain = data.get("domain", "").strip()

        if not domain:
            return jsonify({"success": False, "error": "No domain specified."}), 400

        try:
            result = investigate_domain_complete(domain)
            record_domain_investigation(domain, result)
            return jsonify(result)
        except Exception as e:
            return jsonify({"success": False, "error": f"Domain inspection error: {str(e)}"}), 500

    @app.route("/api/chatbot", methods=["POST"])
    def api_chatbot():
        """SENTRIX AI Chat Assistant Orchestrator"""
        data = request.get_json() or {}
        message = data.get("message", "").strip()
        context_url = data.get("context_url")

        if not message:
            return jsonify({"success": False, "error": "Empty message."}), 400

        # Retrieve user configured Gemini API key (or environment variable fallback)
        settings = UserSettings.query.first()
        user_key = (settings.gemini_api_key if settings and settings.gemini_api_key else None) or app.config.get("GEMINI_API_KEY", "")

        # Fetch recent chat turns for contextual memory
        recent_chats = ChatMessage.query.order_by(
            ChatMessage.created_at.desc()
        ).limit(6).all()
        history = [
            {"sender": c.sender, "message": c.message}
            for c in reversed(recent_chats)
        ]

        context_data = data.get("context_data")

        reply = process_chat_message(
            message=message,
            user_api_key=user_key,
            context_url=context_url,
            history=history,
            context_data=context_data
        )

        # Save to database
        db.session.add(ChatMessage(sender="user", message=message, context_url=context_url))
        db.session.add(ChatMessage(sender="assistant", message=reply, context_url=context_url))
        db.session.commit()

        return jsonify({"success": True, "reply": reply})

    @app.route("/api/chatbot/clear", methods=["POST"])
    def api_clear_chat():
        """Clears assistant conversation history"""
        ChatMessage.query.delete()
        db.session.commit()
        return jsonify({"success": True})

    @app.route("/api/save-query", methods=["POST"])
    def api_save_query():
        """Saves a custom query template"""
        data = request.get_json() or {}
        domain = data.get("domain", "General")
        query_title = data.get("query_title", "Custom Dork")
        query_text = data.get("query_text", "")
        category = data.get("category", "Custom")

        if not query_text:
            return jsonify({"success": False, "error": "Empty query."}), 400

        new_q = SavedQuery(
            target_domain=domain,
            category=category,
            query_title=query_title,
            query_text=query_text
        )
        db.session.add(new_q)
        db.session.commit()
        return jsonify({"success": True, "id": new_q.id})

    @app.route("/osint/export", methods=["GET"])
    def export_osint():
        """Exports generated OSINT queries as TXT or CSV"""
        domain = request.args.get("domain", "example.com").strip()
        export_format = request.args.get("format", "txt").lower()

        dork_data = generate_dorks_for_domain(domain, "all")

        if export_format == "csv":
            csv_content = export_queries_csv(dork_data)
            return Response(
                csv_content,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=SENTRIX-OSINT-{domain}.csv"}
            )
        else:
            txt_content = export_queries_txt(dork_data)
            return Response(
                txt_content,
                mimetype="text/plain",
                headers={"Content-Disposition": f"attachment; filename=SENTRIX-OSINT-{domain}.txt"}
            )

    @app.route("/api/download-report/<uuid>", methods=["GET"])
    def download_report(uuid):
        """Downloads Investigation Report in PDF, CSV, or TXT format"""
        inv = Investigation.query.filter_by(uuid=uuid).first_or_404()
        export_format = request.args.get("format", "pdf").lower()

        # Construct payload for report generator
        inv_payload = {
            "uuid": inv.uuid,
            "target": inv.target_input,
            "target_type": inv.target_type,
            "risk_score": inv.risk_score,
            "risk_level": inv.risk_level,
            "summary": inv.summary,
            "timestamp": inv.created_at.strftime("%Y-%m-%d %H:%M UTC") if inv.created_at else "N/A"
        }

        if inv.url_analysis:
            ua = inv.url_analysis
            inv_payload["anatomy"] = {
                "protocol": ua.protocol,
                "hostname": ua.hostname,
                "domain": ua.domain,
                "tld": ua.tld,
                "port": ua.port,
                "path": ua.path,
                "query_params": ua.get_query_params(),
                "host_entropy": "N/A"
            }
            inv_payload["indicators"] = ua.get_indicators()
            inv_payload["recommendations"] = ua.get_recommendations()
        else:
            inv_payload["indicators"] = []
            inv_payload["recommendations"] = [
                "Verify authoritative DNS zone records regularly.",
                "Enforce HSTS and Content-Security-Policy headers."
            ]

        if export_format == "pdf":
            pdf_bytes = generate_pdf_report(inv_payload)
            response = make_response(pdf_bytes)
            response.headers["Content-Type"] = "application/pdf"
            response.headers["Content-Disposition"] = f"attachment; filename=SENTRIX-Audit-{inv.uuid}.pdf"
            return response
        elif export_format == "csv":
            csv_str = generate_csv_report(inv_payload)
            return Response(
                csv_str,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=SENTRIX-Audit-{inv.uuid}.csv"}
            )
        else:
            txt_str = generate_txt_report(inv_payload)
            return Response(
                txt_str,
                mimetype="text/plain",
                headers={"Content-Disposition": f"attachment; filename=SENTRIX-Audit-{inv.uuid}.txt"}
            )

    @app.route("/reports/delete/<uuid>", methods=["POST"])
    def delete_report(uuid):
        """Deletes an investigation report by UUID"""
        inv = Investigation.query.filter_by(uuid=uuid).first()
        if not inv:
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "Report not found."}), 404
            flash("Investigation report not found.", "warning")
            return redirect(url_for("reports_view"))

        target_name = inv.target_input
        db.session.delete(inv)
        db.session.commit()

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "success": True,
                "message": f"Report for '{target_name}' ({uuid}) deleted successfully.",
                "deleted_uuid": uuid
            })

        flash(f"Investigation report {uuid} deleted successfully.", "success")
        return redirect(url_for("reports_view"))

    @app.route("/reports/clear-all", methods=["POST"])
    def clear_all_reports():
        """Clears all investigation reports and archives"""
        count = Investigation.query.count()
        Investigation.query.delete()
        URLAnalysis.query.delete()
        DomainInvestigation.query.delete()
        GeneratedReport.query.delete()
        db.session.commit()

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "success": True,
                "message": f"All {count} investigation report archives cleared successfully."
            })

        flash(f"All {count} investigation reports have been cleared.", "info")
        return redirect(url_for("reports_view"))

    @app.route("/settings/save", methods=["POST"])
    def save_settings():
        """Updates user settings"""
        settings = UserSettings.query.first()
        if not settings:
            settings = UserSettings()
            db.session.add(settings)

        settings.analyst_name = request.form.get("analyst_name", "SEC-ANALYST").strip()
        settings.organization = request.form.get("organization", "Cyber Intelligence Division").strip()
        settings.gemini_api_key = request.form.get("gemini_api_key", "").strip()

        db.session.commit()
        flash("Analyst preferences and configuration saved successfully.", "success")
        return redirect(url_for("settings_view"))

    @app.route("/settings/clear-history", methods=["POST"])
    def clear_history():
        """Clears all investigation history"""
        Investigation.query.delete()
        URLAnalysis.query.delete()
        DomainInvestigation.query.delete()
        db.session.commit()
        flash("All investigation archives have been purged.", "info")
        return redirect(url_for("settings_view"))

    # =========================================================================
    # ERROR HANDLERS
    # =========================================================================

    @app.errorhandler(404)
    def handle_404(e):
        return render_template("errors/404.html", active_page=""), 404

    @app.errorhandler(500)
    def handle_500(e):
        return render_template("errors/500.html", active_page=""), 500

    return app


def record_investigation(target_url, target_type, analysis_data):
    """Persists a URL analysis to database"""
    if not analysis_data or not analysis_data.get("success"):
        return None

    anat = analysis_data.get("anatomy", {})
    risk = analysis_data.get("risk", {})

    case_uuid = f"STX-2026-{uuid.uuid4().hex[:6].upper()}"

    inv = Investigation(
        uuid=case_uuid,
        target_type=target_type,
        target_input=target_url,
        risk_score=risk.get("score", 0),
        risk_level=risk.get("classification", "LOW"),
        summary=risk.get("summary", ""),
        is_demo=False
    )
    db.session.add(inv)
    db.session.flush()

    ua = URLAnalysis(
        investigation_id=inv.id,
        url=target_url,
        protocol=anat.get("protocol"),
        hostname=anat.get("hostname"),
        domain=anat.get("domain"),
        tld=anat.get("tld"),
        port=str(anat.get("port")),
        path=anat.get("path"),
        query_params_json=json.dumps(anat.get("query_params", {})),
        indicators_json=json.dumps(risk.get("indicators", [])),
        recommendations_json=json.dumps(analysis_data.get("recommendations", []))
    )
    db.session.add(ua)
    db.session.commit()
    return inv


def record_domain_investigation(domain, intel_data):
    """Persists a domain investigation to database"""
    if not intel_data or not intel_data.get("success"):
        return None

    case_uuid = f"STX-DOM-{uuid.uuid4().hex[:6].upper()}"

    inv = Investigation(
        uuid=case_uuid,
        target_type="domain",
        target_input=domain,
        risk_score=25 if intel_data.get("posture", {}).get("risk_factors") else 10,
        risk_level="MEDIUM" if intel_data.get("posture", {}).get("risk_factors") else "LOW",
        summary=f"Domain intelligence audit for {domain}. {intel_data.get('dns', {}).get('total_records_found', 0)} DNS records retrieved.",
        is_demo=False
    )
    db.session.add(inv)
    db.session.flush()

    dns_recs = intel_data.get("dns", {}).get("records", {})
    primary_ip = dns_recs.get("A", [{}])[0].get("value") if dns_recs.get("A") else "N/A"

    di = DomainInvestigation(
        investigation_id=inv.id,
        domain=domain,
        ip_address=primary_ip,
        dns_records_json=json.dumps(dns_recs),
        ssl_data_json=json.dumps(intel_data.get("ssl", {})),
        headers_data_json=json.dumps(intel_data.get("headers", {})),
        whois_data_json=json.dumps(intel_data.get("whois", {}))
    )
    db.session.add(di)
    db.session.commit()
    return inv


def seed_initial_data():
    """Seeds baseline settings and realistic demo investigations if empty"""
    if not UserSettings.query.first():
        default_settings = UserSettings(
            analyst_name="SEC-ANALYST-77",
            organization="Cyber Defense Directorate",
            theme="dark",
            max_redirect_hops=5
        )
        db.session.add(default_settings)
        db.session.commit()

    if Investigation.query.count() == 0:
        demo_cases = [
            {
                "uuid": "STX-2026-DEMO1",
                "target_type": "url",
                "target_input": "https://paypa1-account-security-update.com/login?token=x991",
                "risk_score": 90,
                "risk_level": "CRITICAL",
                "summary": "High-confidence brand spoofing detected against PayPal institution with credential harvesting query tokens.",
                "indicators": [
                    {
                        "name": "Potential Brand Spoofing (Paypal)",
                        "severity": "CRITICAL",
                        "score_impact": 45,
                        "evidence": "Character Substitution: paypa1 -> paypal",
                        "technical_explanation": "Homoglyph substitution (number 1 in place of letter l) crafted to harvest financial credentials.",
                        "precaution": "Block domain at perimeter DNS resolvers."
                    },
                    {
                        "name": "Sensitive Query Parameter",
                        "severity": "MEDIUM",
                        "score_impact": 20,
                        "evidence": "token=x991",
                        "technical_explanation": "Query token observed in authentication workflow.",
                        "precaution": "Never submit credentials or tokens."
                    }
                ]
            },
            {
                "uuid": "STX-2026-DEMO2",
                "target_type": "url",
                "target_input": "http://185.220.101.5:8080/admin/payload.php",
                "risk_score": 75,
                "risk_level": "CRITICAL",
                "summary": "Direct raw IP hostname binding on non-standard port 8080 over unencrypted HTTP.",
                "indicators": [
                    {
                        "name": "IP-Based Hostname",
                        "severity": "HIGH",
                        "score_impact": 35,
                        "evidence": "Direct IP: 185.220.101.5",
                        "technical_explanation": "Direct IP endpoints bypass domain reputation filtering and frequently host malware command-and-control nodes.",
                        "precaution": "Restrict outbound egress connections to bare IP destinations."
                    },
                    {
                        "name": "Insecure HTTP Transport",
                        "severity": "MEDIUM",
                        "score_impact": 20,
                        "evidence": "Protocol: http://",
                        "technical_explanation": "Cleartext transport allows traffic sniffing and tampering.",
                        "precaution": "Require TLS 1.3 encryption."
                    }
                ]
            },
            {
                "uuid": "STX-2026-DEMO3",
                "target_type": "domain",
                "target_input": "github.com",
                "risk_score": 10,
                "risk_level": "LOW",
                "summary": "Authoritative enterprise infrastructure with active DMARC, valid TLS 1.3 certificates, and robust HTTP security headers.",
                "indicators": []
            },
            {
                "uuid": "STX-2026-DEMO4",
                "target_type": "url",
                "target_input": "https://bit.ly/3xSecurityUpdate",
                "risk_score": 35,
                "risk_level": "MEDIUM",
                "summary": "URL shortening service masking intermediary destination hops.",
                "indicators": [
                    {
                        "name": "URL Shortening Service",
                        "severity": "MEDIUM",
                        "score_impact": 25,
                        "evidence": "Shortener Host: bit.ly",
                        "technical_explanation": "Obscures real destination to bypass email perimeter filters.",
                        "precaution": "Trace redirects prior to navigating."
                    }
                ]
            }
        ]

        for case in demo_cases:
            inv = Investigation(
                uuid=case["uuid"],
                target_type=case["target_type"],
                target_input=case["target_input"],
                risk_score=case["risk_score"],
                risk_level=case["risk_level"],
                summary=case["summary"],
                is_demo=True
            )
            db.session.add(inv)
            db.session.flush()

            if case["target_type"] == "url":
                ua = URLAnalysis(
                    investigation_id=inv.id,
                    url=case["target_input"],
                    protocol="https" if "https" in case["target_input"] else "http",
                    hostname=case["target_input"].split("://")[1].split("/")[0],
                    domain="example.com",
                    tld=".com",
                    port="443" if "https" in case["target_input"] else "80",
                    path="/" + "/".join(case["target_input"].split("://")[1].split("/")[1:]),
                    query_params_json="{}",
                    indicators_json=json.dumps(case.get("indicators", [])),
                    recommendations_json=json.dumps(["Maintain continuous threat intelligence logging."])
                )
                db.session.add(ua)

        db.session.commit()


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    print(f"""
    ======================================================================
    SENTRIX SECURITY ANALYSIS & URL INTELLIGENCE PLATFORM
    INVESTIGATE. ANALYZE. UNDERSTAND. PROTECT.
    ======================================================================
    Starting SENTRIX Cyber Intelligence Command Center on port {port}
    """)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
