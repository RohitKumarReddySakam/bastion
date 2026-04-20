import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'bastion.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AUDIT_TIMEOUT = int(os.environ.get("AUDIT_TIMEOUT", "15"))
