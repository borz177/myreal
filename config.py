from dotenv import load_dotenv
import os
from datetime import timedelta
from urllib.parse import quote_plus
from urllib.parse import quote_plus, urlparse, urlunparse
from extensions import db

app_env = os.getenv("APP_ENV", "development")
dotenv_path = f".env.{app_env}"
load_dotenv(dotenv_path)
print("APP_ENV:", app_env)
print("dotenv_path:", dotenv_path)
print("DATABASE_URL:", repr(os.getenv("DATABASE_URL")))

class Config:



    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret")
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Сессии
    SESSION_TYPE = 'sqlalchemy'  # Хранение сессий в базе данных
    SESSION_SQLALCHEMY = db  # Используем текущую базу данных для сессий
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    REMEMBER_COOKIE_DURATION = timedelta(days=30)

    # ❗ Безопасность cookie только в проде
    if app_env == "development":
        SESSION_COOKIE_SECURE = False  # Разрешает использование HTTP
        SESSION_COOKIE_SAMESITE = "Lax"  # Совместимо с OAuth редиректами
    else:
        SESSION_COOKIE_SECURE = True  # Только HTTPS в продакшене
        SESSION_COOKIE_SAMESITE = "None"  # Разрешает сторонние куки (OAuth и др.)

    SESSION_COOKIE_HTTPONLY = True  # Защита от доступа через JS

    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

    # Redirect URI
    if app_env == "development":
        GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000/auth/callback"
    else:
        GOOGLE_REDIRECT_URI = "https://rassrochk.ru/auth/callback"


