# Secure File Vault

## Why this project exists

Students and small teams share sensitive files — marksheets, IDs, offer
letters — over WhatsApp and email, where the file lives forever and
anyone with the link can open it. Secure File Vault gives them
password-protected, expiring, audited sharing instead: upload a file,
get a link that dies on a timer, and see exactly who downloaded what.

## What it does

- **Register / log in** — passwords are hashed with Werkzeug (PBKDF2);
  the plain password is never stored. Sessions use Flask-Login.
- **Upload** — the file is encrypted with AES (Fernet: AES-128-CBC +
  HMAC) *before* it is written to disk. Only encrypted bytes are
  stored. The original filename is kept in the database and never
  used as a file path, so a filename like `../../etc/passwd` cannot
  escape the upload folder.
- **Share** — each link gets a random unguessable token
  (`secrets.token_urlsafe`), an expiry time (1 hour – 30 days), an
  optional download limit and an optional share password (also
  hashed). Downloads check expiry, download count and password
  *before* decrypting anything.
- **Audit** — every register, login, upload, share, download and
  delete is written to an audit table and shown on the dashboard.
- **Delete** — removes the encrypted file from disk and its database
  record (and its share links).
- **Safety checks** — 16 MB size limit, an allow-list of file types
  (no executables or scripts), and `secure_filename` on uploads.

## How encryption + auth work

1. On first run, `crypto_utils.py` generates a Fernet key and saves it
   in `instance/vault.key`. That file is in `.gitignore` and must never
   be committed — lose the key and the stored files cannot be
   recovered.
2. Upload: `encrypt_bytes(file_bytes)` → the `.enc` bytes are saved
   under a random UUID name in `instance/uploads/`.
3. Download: the app checks the share link (not expired, under its
   download limit, share password correct if one is set), then
   `decrypt_bytes(...)` and streams the original file back.
   The decrypted file is never written to disk.

## How to run locally

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

Register an account, upload a file, create a share link from the
dashboard, and open the link in a private/incognito window to see
the public download page. To run the tests:

```bash
python -m pytest tests/ -v
```

Set `VAULT_SECRET_KEY` in the environment for anything beyond local
testing — the default in `app.py` is a dev placeholder.

## Honest limitations

- **Not end-to-end encrypted in the browser.** The server encrypts
  the file after upload and decrypts it for download, so the server
  (and anyone with the vault key) can read the files. A true
  end-to-end system would encrypt in the browser before upload.
- **Not a replacement for Google Drive.** Single-server Flask app,
  SQLite database, files on local disk — no scaling, no backups,
  no redundancy.
- **No key rotation or breach recovery yet.** If `instance/vault.key`
  leaks, every stored file is readable; there is no way to re-key
  existing files, and no way to recover files if the key is lost.
- **No email notifications or two-factor auth.** Share links are
  only as safe as the channel you send them through.

## How to explain this in an interview

"I built a file-sharing app for sensitive student documents, because
sharing marksheets over WhatsApp leaves the file lying around
forever. In Flask I added register and login with hashed passwords,
and when a file is uploaded I encrypt it with AES using Fernet before
writing it to disk — the stored file is useless without the key. A
share link gets a random token, an expiry time, an optional download
limit and an optional password, and the app checks all of those
before decrypting anything. Every upload, share and download is
written to an audit log on the dashboard. The honest limitation is
that the encryption happens on the server, not in the browser, so it
is not true end-to-end encryption — and there is no key rotation yet."
