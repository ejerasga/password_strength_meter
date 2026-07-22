from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class WeakPattern(db.Model):
    """A community-contributed pattern the strength checker should flag.

    Shared across all concurrent users -- anyone contributing a pattern
    (e.g. "companyname" or a regex like /\\d{4}-\\d{2}/) strengthens the
    checker for everyone, immediately, without a restart.
    """

    __tablename__ = "weak_patterns"

    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(200), unique=True, nullable=False)
    label = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    hits = db.Column(db.Integer, default=0, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "label": self.label,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "hits": self.hits,
        }


class ShortLink(db.Model):
    """A shortened URL. Anyone can create one; only the creator's browser
    can delete it, proven by holding the one-time `delete_token` -- there
    is no login system, so this is the same "anonymous but yours" model
    classic free shorteners (tinyurl, is.gd) use.
    """

    __tablename__ = "short_links"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    target_url = db.Column(db.Text, nullable=False)
    delete_token = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    clicks = db.Column(db.Integer, default=0, nullable=False)

    def to_dict(self, host_url: str | None = None, include_token: bool = False) -> dict:
        data = {
            "id": self.id,
            "slug": self.slug,
            "target_url": self.target_url,
            "short_url": (host_url.rstrip("/") + "/" + self.slug) if host_url else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "clicks": self.clicks,
        }
        if include_token:
            data["delete_token"] = self.delete_token
        return data
