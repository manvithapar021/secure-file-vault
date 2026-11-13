"""Tests for Secure File Vault.

Run from the project root:  python -m pytest tests/ -v
"""
import io
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto_utils  # noqa: E402
import app as vault  # noqa: E402


@pytest.fixture()
def client(tmp_path):
    """A test client with a fresh temp database, temp upload folder and
    a temp encryption key — nothing touches the real instance/ dir."""
    instance = tmp_path / "instance"
    uploads = instance / "uploads"
    uploads.mkdir(parents=True)
    crypto_utils.KEY_PATH = str(instance / "vault.key")
    vault.UPLOAD_DIR = str(uploads)
    vault.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + str(instance / "vault.db")
    vault.app.config["TESTING"] = True
    vault.app.config["WTF_CSRF_ENABLED"] = False
    with vault.app.app_context():
        vault.db.create_all()
    with vault.app.test_client() as c:
        yield c
    with vault.app.app_context():
        vault.db.drop_all()


def register(client, username="manvi", password="secret123"):
    return client.post(
        "/register", data={"username": username, "password": password}, follow_redirects=True
    )


def upload_file(client, name="marksheet.pdf", content=b"FAKE PDF CONTENT"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(content), name)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_encryption_round_trip():
    """encrypt_bytes output is not the plaintext, and decrypts back."""
    plain = b"my marksheet, very secret"
    token = crypto_utils.encrypt_bytes(plain)
    assert token != plain
    assert crypto_utils.decrypt_bytes(token) == plain


def test_register_login_and_upload(client):
    register(client)
    resp = upload_file(client)
    assert resp.status_code == 200
    assert b"marksheet.pdf" in resp.data
    # The file on disk is encrypted, not the plain text.
    stored = list(os.listdir(os.path.join(os.path.dirname(vault.UPLOAD_DIR), "uploads")))
    assert len(stored) == 1
    with open(os.path.join(vault.UPLOAD_DIR, stored[0]), "rb") as f:
        assert b"FAKE PDF CONTENT" not in f.read()


def test_unauthenticated_access_blocked(client):
    """Dashboard and upload without logging in redirect to /login."""
    assert client.get("/dashboard").status_code == 302
    assert "/login" in client.get("/dashboard").headers["Location"]
    resp = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"x"), "a.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302


def test_share_link_download_and_limit(client):
    register(client)
    upload_file(client)
    with vault.app.app_context():
        f = vault.VaultFile.query.first()
        file_id = f.id
    # Share with a limit of 1 download, expiring in 24h.
    resp = client.post(
        f"/files/{file_id}/share",
        data={"expiry_hours": "24", "max_downloads": "1", "share_password": ""},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with vault.app.app_context():
        link = vault.ShareLink.query.first()
        token = link.token
    # First download works and returns the original content.
    resp = client.get(f"/s/{token}/download")
    assert resp.status_code == 200
    assert resp.data == b"FAKE PDF CONTENT"
    # Second download is blocked: the limit is reached.
    assert client.get(f"/s/{token}/download").status_code == 410


def test_expired_link_rejected(client):
    register(client)
    upload_file(client)
    with vault.app.app_context():
        f = vault.VaultFile.query.first()
        link = vault.ShareLink(
            file_id=f.id,
            token="expired-token-for-test",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        vault.db.session.add(link)
        vault.db.session.commit()
    assert client.get("/s/expired-token-for-test").status_code == 410
    assert client.get("/s/expired-token-for-test/download").status_code == 410


def test_share_password_required(client):
    register(client)
    upload_file(client)
    with vault.app.app_context():
        f = vault.VaultFile.query.first()
        file_id = f.id
    client.post(
        f"/files/{file_id}/share",
        data={"expiry_hours": "24", "max_downloads": "", "share_password": "letmein"},
        follow_redirects=True,
    )
    with vault.app.app_context():
        token = vault.ShareLink.query.first().token
    # Without the password, the download redirects to the password page.
    resp = client.get(f"/s/{token}/download")
    assert resp.status_code == 302
    # Wrong password is refused; right password unlocks the download.
    assert b"Wrong share password" in client.post(
        f"/s/{token}", data={"password": "nope"}, follow_redirects=True
    ).data
    client.post(f"/s/{token}", data={"password": "letmein"}, follow_redirects=True)
    assert client.get(f"/s/{token}/download").data == b"FAKE PDF CONTENT"


def test_delete_removes_file_and_record(client):
    register(client)
    upload_file(client)
    with vault.app.app_context():
        f = vault.VaultFile.query.first()
        file_id, path = f.id, f.disk_path
    assert os.path.exists(path)
    client.post(f"/files/{file_id}/delete", follow_redirects=True)
    assert not os.path.exists(path)
    with vault.app.app_context():
        assert vault.VaultFile.query.count() == 0
