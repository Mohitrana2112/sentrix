"""
SENTRIX Application Configuration
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env if present
load_dotenv(BASE_DIR / ".env")


class Config:
    # Security Secrets
    SECRET_KEY = os.environ.get("SECRET_KEY", "sentrix-cyber-intel-key-v2-super-secret-2026")

    # Database Configuration (PostgreSQL compatible, SQLite default)
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        # Fix Render/Heroku postgres:// prefix to postgresql:// for SQLAlchemy 2.x
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        SQLALCHEMY_DATABASE_URI = db_url
    else:
        instance_dir = BASE_DIR / "instance"
        instance_dir.mkdir(parents=True, exist_ok=True)
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{instance_dir.as_posix()}/sentrix.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AI Integration Credentials
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

    # Security & Session Settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    # Application Branding Metadata
    PRODUCT_NAME = "SENTRIX"
    PRODUCT_FULL_NAME = "Security Analysis & URL Intelligence"
    TAGLINE = "INVESTIGATE. ANALYZE. UNDERSTAND. PROTECT."
    VERSION = "2.4.0 PRO"
