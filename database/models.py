"""
SENTRIX Database Models
PostgreSQL-compatible SQLite schema for investigations, telemetry, queries, and reports.
"""

import datetime
import json
from database.db import db


class Investigation(db.Model):
    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    target_type = db.Column(db.String(32), nullable=False, default="url")  # 'url' or 'domain'
    target_input = db.Column(db.String(512), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_level = db.Column(db.String(16), nullable=False, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    summary = db.Column(db.Text, nullable=True)
    is_demo = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    # Relationships
    url_analysis = db.relationship("URLAnalysis", backref="investigation", uselist=False, cascade="all, delete-orphan")
    domain_investigation = db.relationship("DomainInvestigation", backref="investigation", uselist=False, cascade="all, delete-orphan")
    reports = db.relationship("GeneratedReport", backref="investigation", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "uuid": self.uuid,
            "target_type": self.target_type,
            "target_input": self.target_input,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "is_demo": self.is_demo,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }


class URLAnalysis(db.Model):
    __tablename__ = "url_analyses"

    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.Integer, db.ForeignKey("investigations.id"), nullable=False)
    url = db.Column(db.String(1024), nullable=False)
    protocol = db.Column(db.String(16))
    hostname = db.Column(db.String(256))
    domain = db.Column(db.String(256))
    tld = db.Column(db.String(64))
    port = db.Column(db.String(16))
    path = db.Column(db.String(1024))
    query_params_json = db.Column(db.Text, default="{}")
    indicators_json = db.Column(db.Text, default="[]")
    recommendations_json = db.Column(db.Text, default="[]")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def get_query_params(self):
        return json.loads(self.query_params_json or "{}")

    def get_indicators(self):
        return json.loads(self.indicators_json or "[]")

    def get_recommendations(self):
        return json.loads(self.recommendations_json or "[]")


class DomainInvestigation(db.Model):
    __tablename__ = "domain_investigations"

    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.Integer, db.ForeignKey("investigations.id"), nullable=False)
    domain = db.Column(db.String(256), nullable=False)
    ip_address = db.Column(db.String(64))
    dns_records_json = db.Column(db.Text, default="{}")
    ssl_data_json = db.Column(db.Text, default="{}")
    headers_data_json = db.Column(db.Text, default="{}")
    whois_data_json = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def get_dns(self):
        return json.loads(self.dns_records_json or "{}")

    def get_ssl(self):
        return json.loads(self.ssl_data_json or "{}")

    def get_headers(self):
        return json.loads(self.headers_data_json or "{}")

    def get_whois(self):
        return json.loads(self.whois_data_json or "{}")


class SavedQuery(db.Model):
    __tablename__ = "saved_queries"

    id = db.Column(db.Integer, primary_key=True)
    target_domain = db.Column(db.String(256), nullable=False)
    category = db.Column(db.String(64), nullable=False)
    query_title = db.Column(db.String(256), nullable=False)
    query_text = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class GeneratedReport(db.Model):
    __tablename__ = "generated_reports"

    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.Integer, db.ForeignKey("investigations.id"), nullable=False)
    report_uuid = db.Column(db.String(64), unique=True, nullable=False)
    target = db.Column(db.String(512), nullable=False)
    format = db.Column(db.String(16), nullable=False, default="PDF")  # PDF, CSV, TXT
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class UserSettings(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    theme = db.Column(db.String(16), default="dark")  # 'dark' or 'light'
    analyst_name = db.Column(db.String(128), default="SEC-ANALYST-77")
    organization = db.Column(db.String(128), default="Cyber Intelligence Division")
    gemini_api_key = db.Column(db.String(256), nullable=True)
    auto_resolve_dns = db.Column(db.Boolean, default=True)
    enable_notifications = db.Column(db.Boolean, default=True)
    max_redirect_hops = db.Column(db.Integer, default=5)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(16), nullable=False)  # 'user' or 'assistant'
    message = db.Column(db.Text, nullable=False)
    context_url = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
