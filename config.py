"""
WebShield Configuration
Reads all settings from environment variables loaded by python-dotenv.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Flask
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")
    DEBUG: bool = False
    TESTING: bool = False

    # SQLAlchemy
    _db_host = os.environ.get("DB_HOST", "localhost")
    _db_port = os.environ.get("DB_PORT", "3306")
    _db_name = os.environ.get("DB_NAME", "webshield")
    _db_user = os.environ.get("DB_USER", "root")
    _db_pass = os.environ.get("DB_PASSWORD", "")
    _mysql_uri = f"mysql+pymysql://{_db_user}:{_db_pass}@{_db_host}:{_db_port}/{_db_name}"
    SQLALCHEMY_DATABASE_URI: str = os.environ.get("DATABASE_URL", _mysql_uri)
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    # WTF / CSRF
    WTF_CSRF_ENABLED: bool = True

    # Scanner safety
    SCANNER_TIMEOUT: int = int(os.environ.get("SCANNER_TIMEOUT", "15"))
    SCANNER_MAX_RESPONSE_SIZE: int = int(
        os.environ.get("SCANNER_MAX_RESPONSE_SIZE", str(5 * 1024 * 1024))
    )
    SCANNER_MAX_REQUESTS_PER_SCAN: int = int(
        os.environ.get("SCANNER_MAX_REQUESTS_PER_SCAN", "20")
    )
    RATE_LIMIT_PER_MINUTE: int = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "10"))

    # Optional allowlist (comma-separated hostnames).  Empty = permissive dev mode.
    SCAN_ALLOWLIST: list[str] = [
        h.strip()
        for h in os.environ.get("SCAN_ALLOWLIST", "").split(",")
        if h.strip()
    ]

    DEMO_MODE: bool = os.environ.get("DEMO_MODE", "0").strip() == "1"


class DevelopmentConfig(Config):
    DEBUG: bool = True


class ProductionConfig(Config):
    DEBUG: bool = False
    WTF_CSRF_ENABLED: bool = True


class TestingConfig(Config):
    TESTING: bool = True
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    WTF_CSRF_ENABLED: bool = False
    DEMO_MODE: bool = True
    SCAN_ALLOWLIST: list[str] = []


_configs = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config() -> type[Config]:
    env = os.environ.get("FLASK_ENV", "development")
    return _configs.get(env, DevelopmentConfig)
