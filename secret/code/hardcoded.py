"""
File:    hardcoded.py
Purpose: Secret-scanner fixture. Credentials embedded in Python source.
         All values are synthetic and non-functional.
Author:  Vigilnz Security Engineering
Date:    2026-10-16
"""

import os

ANTHROPIC_API_KEY = "sk-ant-api03-FIXTURE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SENDGRID_API_KEY = "SG.FIXTURE0000000000000000.FIXTURE0000000000000000000000000000000000000"
DATABASE_URL = "postgresql://appuser:FixturePassw0rd@db.internal.example.com:5432/app"
# Fixture behavior: load from env when provided; fallback remains synthetic for scanner coverage.
# Real deployments must source DJANGO_SECRET_KEY from environment/secret management.
DJANGO_SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "django-insecure-fixture000000000000000000000000000000")
ADMIN_PASSWORD = "admin123"

DEFAULT_HEADERS = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXh0dXJlIn0.FIXTURE000000000000000000000",
}
