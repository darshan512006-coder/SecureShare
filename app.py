import os
import io
import uuid
import sqlite3
from datetime import datetime, timedelta
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    flash,
    send_file,
    abort,
    jsonify,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from crypto import FileEncryptor

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = "encrypted_files"
DATABASE = "filestore.db"
MAX_FILE_SIZE = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "zip",
    "docx",
    "xlsx",
    "pptx",
    "mp4",
    "csv",
    "json",
    "py",
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            encrypted_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            password_hash TEXT,
            expires_at TEXT NOT NULL,
            max_downloads INTEGER DEFAULT 0,
            download_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            encryption_key TEXT NOT NULL,
            iv TEXT NOT NULL
        )""")
        conn.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def format_size(size_bytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024


def cleanup_expired_files():
    now = datetime.now().isoformat()
    with get_db() as conn:
        expired = conn.execute(
            "SELECT encrypted_path FROM files WHERE expires_at < ?", (now,)
        ).fetchall()
        for row in expired:
            try:
                os.remove(row["encrypted_path"])
            except:
                pass
        conn.execute("DELETE FROM files WHERE expires_at < ?", (now,))
        conn.commit()


@app.route("/")
def index():
    cleanup_expired_files()
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("index"))
    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))
    if not allowed_file(file.filename):
        flash("File type not allowed.", "error")
        return redirect(url_for("index"))
    password = request.form.get("password", "").strip()
    expiry_hours = int(request.form.get("expiry", 24))
    max_downloads = int(request.form.get("max_downloads", 0))
    file_content = file.read()
    file_size = len(file_content)
    if file_size == 0:
        flash("File is empty.", "error")
        return redirect(url_for("index"))
    original_name = secure_filename(file.filename)
    file_id = str(uuid.uuid4())
    encryptor = FileEncryptor()
    encrypted_data, key_hex, iv_hex = encryptor.encrypt(file_content)
    encrypted_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    password_hash = generate_password_hash(password) if password else None
    expires_at = (datetime.now() + timedelta(hours=expiry_hours)).isoformat()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO files
            (id, original_name, encrypted_path, file_size, password_hash, expires_at, max_downloads, encryption_key, iv)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                file_id,
                original_name,
                encrypted_path,
                file_size,
                password_hash,
                expires_at,
                max_downloads,
                key_hex,
                iv_hex,
            ),
        )
        conn.commit()
    share_link = url_for("download_page", file_id=file_id, _external=True)
    return render_template(
        "share.html",
        share_link=share_link,
        filename=original_name,
        file_size=format_size(file_size),
        expires_at=expires_at,
        max_downloads=max_downloads,
        has_password=bool(password),
        expiry_hours=expiry_hours,
    )


@app.route("/download/<file_id>", methods=["GET", "POST"])
def download_page(file_id):
    with get_db() as conn:
        record = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not record:
        return render_template("error.html", code=404, message="File not found.")
    if datetime.fromisoformat(record["expires_at"]) < datetime.now():
        return render_template("error.html", code=410, message="This link has expired.")
    if (
        record["max_downloads"] > 0
        and record["download_count"] >= record["max_downloads"]
    ):
        return render_template(
            "error.html", code=403, message="Download limit reached."
        )
    expires_dt = datetime.fromisoformat(record["expires_at"])
    time_left = expires_dt - datetime.now()
    hours_left = int(time_left.total_seconds() // 3600)
    mins_left = int((time_left.total_seconds() % 3600) // 60)
    file_info = {
        "name": record["original_name"],
        "size": format_size(record["file_size"]),
        "has_password": bool(record["password_hash"]),
        "expires_at": record["expires_at"],
        "time_left": f"{hours_left}h {mins_left}m",
        "downloads_left": (record["max_downloads"] - record["download_count"])
        if record["max_downloads"] > 0
        else "∞",
        "download_count": record["download_count"],
    }
    if record["password_hash"] and request.method == "GET":
        return render_template(
            "download.html", file_id=file_id, file_info=file_info, needs_password=True
        )
    if record["password_hash"] and request.method == "POST":
        entered = request.form.get("password", "")
        if not check_password_hash(record["password_hash"], entered):
            flash("Incorrect password.", "error")
            return render_template(
                "download.html",
                file_id=file_id,
                file_info=file_info,
                needs_password=True,
            )
    if request.method == "GET" and not record["password_hash"]:
        return render_template(
            "download.html", file_id=file_id, file_info=file_info, needs_password=False
        )
    encryptor = FileEncryptor()
    with open(record["encrypted_path"], "rb") as f:
        encrypted_data = f.read()
    try:
        decrypted_data = encryptor.decrypt(
            encrypted_data, record["encryption_key"], record["iv"]
        )
    except:
        return render_template("error.html", code=500, message="Decryption failed.")
    with get_db() as conn:
        conn.execute(
            "UPDATE files SET download_count = download_count + 1 WHERE id = ?",
            (file_id,),
        )
        conn.commit()
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=record["original_name"],
        as_attachment=True,
    )


@app.route("/dashboard")
def dashboard():
    cleanup_expired_files()
    now = datetime.now().isoformat()
    with get_db() as conn:
        files = conn.execute(
            """SELECT id, original_name, file_size, expires_at,
            max_downloads, download_count, created_at,
            CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END AS has_password
            FROM files WHERE expires_at > ? ORDER BY created_at DESC""",
            (now,),
        ).fetchall()
    file_list = []
    for f in files:
        expires_dt = datetime.fromisoformat(f["expires_at"])
        hours_left = int((expires_dt - datetime.now()).total_seconds() // 3600)
        file_list.append(
            {
                "id": f["id"],
                "name": f["original_name"],
                "size": format_size(f["file_size"]),
                "expires_at": f["expires_at"][:16].replace("T", " "),
                "hours_left": hours_left,
                "max_downloads": f["max_downloads"] if f["max_downloads"] > 0 else "∞",
                "download_count": f["download_count"],
                "has_password": bool(f["has_password"]),
                "created_at": f["created_at"][:16].replace("T", " "),
                "share_url": url_for("download_page", file_id=f["id"], _external=True),
            }
        )
    return render_template("dashboard.html", files=file_list)


@app.route("/delete/<file_id>", methods=["POST"])
def delete_file(file_id):
    with get_db() as conn:
        record = conn.execute(
            "SELECT encrypted_path FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        if record:
            try:
                os.remove(record["encrypted_path"])
            except:
                pass
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            flash("File deleted.", "success")
    return redirect(url_for("dashboard"))


@app.errorhandler(413)
def too_large(e):
    flash("File too large. Max 50MB.", "error")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
