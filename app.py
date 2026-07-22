import os
import secrets
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, redirect, render_template, request

from models import ShortLink, WeakPattern, db
from password_utils import (
    analyze_password,
    generate_from_pattern,
    generate_from_word,
    generate_passphrase,
    generate_random_password,
)
from url_utils import generate_slug, normalize_url, validate_custom_slug

MAX_SLUG_ATTEMPTS = 8

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def create_app() -> Flask:
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    app = Flask(__name__, instance_path=INSTANCE_DIR)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        INSTANCE_DIR, "patterns.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JSON_SORT_KEYS"] = False

    db.init_app(app)
    with app.app_context():
        db.create_all()

    register_routes(app)

    @app.after_request
    def apply_offline_security_headers(response):
        # Enforced, not just promised: the browser will refuse any request
        # this app tries to make to a host other than itself, so nothing
        # here can ever phone home -- accidentally or otherwise.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    return app


def register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/check", methods=["POST"])
    def api_check():
        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")

        if not isinstance(password, str):
            return jsonify({"error": "password must be a string"}), 400
        if len(password) > 256:
            return jsonify({"error": "password too long"}), 400
        if password == "":
            return jsonify({
                "score": 0, "label": "", "crack_time_display": "",
                "entropy_bits": 0, "warning": "", "suggestions": [],
                "matched_patterns": [], "checks": {},
            })

        context = payload.get("context", [])
        if not isinstance(context, list):
            context = []
        context = [str(c)[:64] for c in context][:10]

        patterns = [p.pattern for p in WeakPattern.query.all()]
        result = analyze_password(password, custom_patterns=patterns, user_inputs=context)

        # Track how often each contributed pattern actually catches something,
        # without ever persisting the password itself.
        if result.matched_patterns:
            WeakPattern.query.filter(
                WeakPattern.pattern.in_(result.matched_patterns)
            ).update({WeakPattern.hits: WeakPattern.hits + 1}, synchronize_session=False)
            db.session.commit()

        return jsonify(result.to_dict())

    @app.route("/api/generate", methods=["POST"])
    def api_generate():
        payload = request.get_json(silent=True) or {}
        mode = payload.get("mode", "random")

        try:
            if mode == "random":
                password = generate_random_password(
                    length=int(payload.get("length", 16)),
                    use_upper=bool(payload.get("use_upper", True)),
                    use_lower=bool(payload.get("use_lower", True)),
                    use_digits=bool(payload.get("use_digits", True)),
                    use_symbols=bool(payload.get("use_symbols", True)),
                    avoid_ambiguous=bool(payload.get("avoid_ambiguous", True)),
                )
            elif mode == "passphrase":
                password = generate_passphrase(
                    num_words=int(payload.get("num_words", 4)),
                    separator=str(payload.get("separator", "-"))[:5],
                    capitalize=bool(payload.get("capitalize", True)),
                    add_number=bool(payload.get("add_number", True)),
                    add_symbol=bool(payload.get("add_symbol", True)),
                )
            elif mode == "pattern":
                template = str(payload.get("template", ""))
                password = generate_from_pattern(template)
            elif mode == "leet":
                password = generate_from_word(
                    word=str(payload.get("word", "")),
                    substitution_rate=float(payload.get("substitution_rate", 0.85)),
                    randomize_case=bool(payload.get("randomize_case", True)),
                    add_digits=bool(payload.get("add_digits", True)),
                    add_symbol=bool(payload.get("add_symbol", True)),
                )
            else:
                return jsonify({"error": "unknown mode"}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        patterns = [p.pattern for p in WeakPattern.query.all()]
        result = analyze_password(password, custom_patterns=patterns)
        return jsonify({"password": password, "analysis": result.to_dict()})

    @app.route("/api/patterns", methods=["GET"])
    def list_patterns():
        patterns = WeakPattern.query.order_by(WeakPattern.created_at.desc()).all()
        return jsonify([p.to_dict() for p in patterns])

    @app.route("/api/patterns", methods=["POST"])
    def add_pattern():
        payload = request.get_json(silent=True) or {}
        pattern = str(payload.get("pattern", "")).strip()
        label = str(payload.get("label", "")).strip()[:120] or None

        if not pattern:
            return jsonify({"error": "pattern is required"}), 400
        if len(pattern) > 200:
            return jsonify({"error": "pattern must be 200 characters or fewer"}), 400

        existing = WeakPattern.query.filter_by(pattern=pattern).first()
        if existing:
            return jsonify(existing.to_dict()), 200

        entry = WeakPattern(pattern=pattern, label=label)
        db.session.add(entry)
        db.session.commit()
        return jsonify(entry.to_dict()), 201

    @app.route("/api/patterns/<int:pattern_id>", methods=["DELETE"])
    def delete_pattern(pattern_id: int):
        entry = WeakPattern.query.get_or_404(pattern_id)
        db.session.delete(entry)
        db.session.commit()
        return "", 204

    # -------------------------------------------------------------
    # URL shortener
    # -------------------------------------------------------------
    @app.route("/api/shorten", methods=["POST"])
    def api_shorten():
        payload = request.get_json(silent=True) or {}

        try:
            target = normalize_url(str(payload.get("url", "")))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Refuse to shorten a link back to this app itself (redirect loop).
        if urlparse(target).netloc.split(":")[0] == request.host.split(":")[0]:
            return jsonify({"error": "Can't shorten a link back to this app."}), 400

        custom_slug = str(payload.get("slug", "")).strip()
        if custom_slug:
            try:
                slug = validate_custom_slug(custom_slug)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            if ShortLink.query.filter_by(slug=slug).first():
                return jsonify({"error": "That custom link is already taken."}), 409
        else:
            for _ in range(MAX_SLUG_ATTEMPTS):
                slug = generate_slug()
                if not ShortLink.query.filter_by(slug=slug).first():
                    break
            else:
                return jsonify({"error": "Could not generate a unique link -- try again."}), 500

        entry = ShortLink(slug=slug, target_url=target, delete_token=secrets.token_urlsafe(24))
        db.session.add(entry)
        db.session.commit()

        return jsonify(entry.to_dict(host_url=request.host_url, include_token=True)), 201

    @app.route("/api/links/<slug>", methods=["GET"])
    def link_info(slug):
        entry = ShortLink.query.filter_by(slug=slug).first_or_404()
        return jsonify(entry.to_dict(host_url=request.host_url))

    @app.route("/api/links/<slug>", methods=["DELETE"])
    def delete_link(slug):
        entry = ShortLink.query.filter_by(slug=slug).first_or_404()
        token = request.headers.get("X-Delete-Token", "")
        if not token or not secrets.compare_digest(token, entry.delete_token):
            return jsonify({"error": "Invalid or missing delete token."}), 403
        db.session.delete(entry)
        db.session.commit()
        return "", 204

    @app.route("/<slug>")
    def follow_link(slug):
        entry = ShortLink.query.filter_by(slug=slug).first()
        if not entry:
            abort(404)
        entry.clicks += 1
        db.session.commit()
        return redirect(entry.target_url, code=302)

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("404.html"), 404


app = create_app()

if __name__ == "__main__":
    # threaded=True lets the dev server serve multiple users' requests
    # concurrently instead of queueing them one at a time.
    # Port 5000 was already taken on this machine, so this defaults to
    # 5050 -- override with the PORT / HOST env vars if needed.
    #
    # HOST defaults to loopback-only. Set HOST=0.0.0.0 to accept connections
    # from other machines (e.g. colleagues on the office LAN reaching this
    # via a DNS/host override) -- but prefer running via waitress for that
    # case; see README.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    if debug and host not in ("127.0.0.1", "localhost"):
        raise RuntimeError(
            f"Refusing to start with FLASK_DEBUG=1 while bound to a "
            f"non-loopback host ({host}). The Werkzeug debugger lets "
            f"anyone who can reach it run arbitrary code on this machine -- "
            f"never enable it on a LAN- or internet-facing address. Drop "
            f"FLASK_DEBUG, or use waitress instead (see README)."
        )

    app.run(debug=debug, threaded=True, host=host, port=port)
