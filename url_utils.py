"""Validation and generation helpers for the URL shortener."""
from __future__ import annotations

import re
import secrets
from urllib.parse import urlparse

SLUG_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")

# Names that must stay reserved so a custom link can never shadow a real
# route (/api/..., /static/...) or a common browser auto-request.
RESERVED_SLUGS = {"api", "static", "favicon.ico", "instance", "robots.txt"}


def normalize_url(raw: str) -> str:
    """Validate a user-submitted URL and return it in canonical form."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Enter a URL to shorten.")
    if len(raw) > 2048:
        raise ValueError("That URL is too long (max 2048 characters).")

    parsed = urlparse(raw)
    if not parsed.scheme:
        parsed = urlparse("https://" + raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// links are allowed.")
    if not parsed.netloc:
        raise ValueError("That doesn't look like a valid URL.")

    return parsed.geturl()


def validate_custom_slug(slug: str) -> str:
    slug = slug.strip()
    if not SLUG_RE.match(slug):
        raise ValueError(
            "Custom links must be 3-32 characters: letters, numbers, - or _ only."
        )
    if slug.lower() in RESERVED_SLUGS:
        raise ValueError("That link name is reserved -- please pick another.")
    return slug


def generate_slug(length: int = 6) -> str:
    return "".join(secrets.choice(SLUG_ALPHABET) for _ in range(length))
