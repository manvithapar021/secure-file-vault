"""Secure File Vault — a Flask app for password-protected, expiring,
audited file sharing.

The problem: students and small teams share sensitive files
(marksheets, IDs, offer letters) over WhatsApp or email, where the
file lives forever and anyone with the link can open it.

What this does instead:
  * Register / log in — passwords are hashed with Werkzeug, never
    stored in plain text. Sessions use Flask-Login.
  * Upload — the file is encrypted with AES (Fernet) before it is
    written to disk. Only the encrypted bytes are stored; the
    original filename is kept in the database, never used as a
    file path (so a filename like "../../etc/passwd" cannot escape
    the upload folder).
  * Share — a link gets a random token (secrets.token_urlsafe), an
    expiry time, an optional download limit and an optional share
    password (also hashed). Downloads check expiry + count +
    password before decrypting.
  * Audit — every upload, share, download and delete is written to
    an audit table and shown on the dashboard.

Stack: Python, Flask, Flask-SQLAlchemy, Flask-Login, cryptography
(Fernet/AES), Werkzeug password hashing, HTML/CSS/JS + Bootstrap 5.
No React, no Node — the whole thing is one Python app.
"""
import io
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from crypto_utils import decrypt_bytes, encrypt_bytes

# ---------------------------------------------------------------- config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(INSTANCE_DIR, "uploads")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("VAULT_SECRET_KEY", "dev-only-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    INSTANCE_DIR, "vault.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Reject anything over 16 MB before it reaches our code.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Only these file types may be uploaded. Executables and scripts are
# blocked on purpose — a vault should not be a way to spread malware.
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "csv", "xlsx", "xls",
    "docx", "doc", "pptx", "zip",
}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------- models


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Hashed with Werkzeug (PBKDF2). The plain password is never stored.
    password_hash = db.Column(db.String(200), nullable=False)
    files = db.relationship("VaultFile", backref="owner", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class VaultFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    # Random name on disk — the user's filename is never a path.
    stored_name = db.Column(db.String(64), unique=True, nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    shares = db.relationship(
        "ShareLink", backref="file", lazy=True, cascade="all, delete-orphan"
    )

    @property
    def disk_path(self) -> str:
        return os.path.join(UPLOAD_DIR, self.stored_name)


class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("vault_file.id"), nullable=False)
    # Random, unguessable token — this is what makes the link private.
    token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    max_downloads = db.Column(db.Integer, nullable=True)  # None = unlimited
    download_count = db.Column(db.Integer, default=0)
    # Optional extra password on the link itself, hashed like logins.
    share_password_hash = db.Column(db.String(200), nullable=True)

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at.replace(
            tzinfo=timezone.utc
        )

    @property
    def is_exhausted(self) -> bool:
        return self.max_downloads is not None and self.download_count >= self.max_downloads

    @property
    def is_usable(self) -> bool:
        return not self.is_expired and not self.is_exhausted

    def needs_password(self) -> bool:
        return self.share_password_hash is not None


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # upload / download / share / delete / login
    detail = db.Column(db.String(255), nullable=False)
    at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def log_action(action: str, detail: str, user_id=None) -> None:
    db.session.add(AuditLog(user_id=user_id, action=action, detail=detail))
    db.session.commit()


# ---------------------------------------------------------------- helpers


def _utcnow():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- routes


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 6:
            flash("Username needs 3+ characters and password 6+ characters.")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("That username is already taken.")
            return render_template("register.html")
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_action("register", f"Account created: {username}", user.id)
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(
            username=request.form.get("username", "").strip()
        ).first()
        if user and user.check_password(request.form.get("password", "")):
            login_user(user)
            log_action("login", f"{user.username} logged in", user.id)
            return redirect(url_for("dashboard"))
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    files = (
        VaultFile.query.filter_by(owner_id=current_user.id)
        .order_by(VaultFile.uploaded_at.desc())
        .all()
    )
    logs = (
        AuditLog.query.filter_by(user_id=current_user.id)
        .order_by(AuditLog.at.desc())
        .limit(20)
        .all()
    )
    return render_template("dashboard.html", files=files, logs=logs, now=_utcnow())


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        flash("Choose a file first.")
        return redirect(url_for("dashboard"))
    if not allowed_file(uploaded.filename):
        flash("That file type is not allowed (no executables or scripts).")
        return redirect(url_for("dashboard"))
    data = uploaded.read()
    if len(data) == 0:
        flash("That file is empty.")
        return redirect(url_for("dashboard"))

    # Encrypt BEFORE writing anything to disk. The .enc file on disk
    # is useless without the vault key.
    stored_name = uuid.uuid4().hex + ".enc"
    with open(os.path.join(UPLOAD_DIR, stored_name), "wb") as f:
        f.write(encrypt_bytes(data))

    vault_file = VaultFile(
        owner_id=current_user.id,
        original_name=secure_filename(uploaded.filename),
        stored_name=stored_name,
        size_bytes=len(data),
    )
    db.session.add(vault_file)
    db.session.commit()
    log_action(
        "upload",
        f"Uploaded {vault_file.original_name} ({len(data)} bytes)",
        current_user.id,
    )
    flash(f"Uploaded and encrypted: {vault_file.original_name}")
    return redirect(url_for("dashboard"))


@app.route("/files/<int:file_id>/share", methods=["POST"])
@login_required
def create_share(file_id):
    vault_file = db.get_or_404(VaultFile, file_id)
    if vault_file.owner_id != current_user.id:
        abort(403)
    try:
        hours = int(request.form.get("expiry_hours", "24"))
    except ValueError:
        hours = 24
    hours = max(1, min(hours, 24 * 30))  # between 1 hour and 30 days
    max_downloads = request.form.get("max_downloads", "").strip()
    max_downloads = int(max_downloads) if max_downloads.isdigit() else None
    share_password = request.form.get("share_password", "").strip()

    link = ShareLink(
        file_id=vault_file.id,
        token=secrets.token_urlsafe(24),
        expires_at=_utcnow() + timedelta(hours=hours),
        max_downloads=max_downloads,
    )
    if share_password:
        link.share_password_hash = generate_password_hash(share_password)
    db.session.add(link)
    db.session.commit()
    log_action(
        "share",
        f"Share link created for {vault_file.original_name} "
        f"(expires in {hours}h, limit {max_downloads or 'unlimited'})",
        current_user.id,
    )
    flash("Share link created — copy it from the file's share list.")
    return redirect(url_for("dashboard"))


@app.route("/files/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    vault_file = db.get_or_404(VaultFile, file_id)
    if vault_file.owner_id != current_user.id:
        abort(403)
    name = vault_file.original_name
    if os.path.exists(vault_file.disk_path):
        os.remove(vault_file.disk_path)
    db.session.delete(vault_file)
    db.session.commit()
    log_action("delete", f"Deleted {name}", current_user.id)
    flash(f"Deleted {name}.")
    return redirect(url_for("dashboard"))


# ------------------------------------------------------- public share links


@app.route("/s/<token>", methods=["GET", "POST"])
def share_page(token):
    link = ShareLink.query.filter_by(token=token).first_or_404()
    if not link.is_usable:
        return render_template(
            "share.html", link=link, error="This link has expired or reached its download limit."
        ), 410
    if link.needs_password():
        # The password is checked once, then remembered in the session
        # for this token only — it is never put in the URL.
        if session.get(f"share_ok_{token}"):
            return render_template("share.html", link=link)
        if request.method == "POST":
            if check_password_hash(
                link.share_password_hash, request.form.get("password", "")
            ):
                session[f"share_ok_{token}"] = True
                return render_template("share.html", link=link)
            return render_template("share.html", link=link, error="Wrong share password.")
        return render_template("share.html", link=link, need_password=True)
    return render_template("share.html", link=link)


@app.route("/s/<token>/download")
def share_download(token):
    link = ShareLink.query.filter_by(token=token).first_or_404()
    if not link.is_usable:
        abort(410, "This link has expired or reached its download limit.")
    if link.needs_password() and not session.get(f"share_ok_{token}"):
        return redirect(url_for("share_page", token=token))
    vault_file = link.file
    if not os.path.exists(vault_file.disk_path):
        abort(404)
    with open(vault_file.disk_path, "rb") as f:
        plain = decrypt_bytes(f.read())
    link.download_count += 1
    db.session.commit()
    log_action(
        "download",
        f"Downloaded {vault_file.original_name} via share link "
        f"({link.download_count}/{link.max_downloads or '∞'})",
        vault_file.owner_id,
    )
    return send_file(
        io.BytesIO(plain),
        as_attachment=True,
        download_name=vault_file.original_name,
    )


@app.errorhandler(413)
def too_large(_e):
    flash("File too large — the limit is 16 MB.")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
