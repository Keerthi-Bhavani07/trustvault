from flask import Flask, render_template, request, session, redirect, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)

from werkzeug.security import generate_password_hash

def create_admin():
    with sqlite3.connect("trustvault.db") as con:
        existing = con.execute(
            "SELECT 1 FROM users WHERE username = ?",
            ("admin",)
        ).fetchone()

        if not existing:
            con.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", generate_password_hash("Admin@12345"), "Admin")
            )

app.secret_key = "change-this-to-a-random-secret-key"

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "png", "jpg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form["role"]

        if not username or len(password) < 8:
            return "Enter a username and password of at least 8 characters.", 400
        if role not in ["Owner", "Viewer"]:
            return "Invalid role.", 400

        try:
            with sqlite3.connect("trustvault.db") as con:
                con.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), role)
                )
            return "Registration successful! <a href='/'>Log in</a>"
        except sqlite3.IntegrityError:
            return "Username already exists. Please choose another."

    return render_template("register.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]

    with sqlite3.connect("trustvault.db") as con:
        user = con.execute(
            "SELECT username, password, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user and check_password_hash(user[1], password):
        session.clear()
        session["username"] = user[0]
        session["role"] = user[2]
        return redirect("/dashboard")

    return "Invalid username or password. <a href='/'>Try again</a>", 401


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/")

    username = session["username"]
    role = session["role"]

    with sqlite3.connect("trustvault.db") as con:
        if role == "Owner":
            documents = con.execute(
                "SELECT id, filename FROM documents WHERE owner = ?",
                (username,)
            ).fetchall()
        else:
            documents = con.execute("""
                SELECT documents.id, documents.filename
                FROM documents
                JOIN document_shares
                ON documents.id = document_shares.document_id
                WHERE document_shares.shared_with = ?
            """, (username,)).fetchall()

    return render_template(
        "dashboard.html",
        username=username,
        role=role,
        documents=documents
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "username" not in session:
        return redirect("/")

    if session["role"] != "Owner":
        return "Access denied: only Owners can upload documents.", 403

    file = request.files.get("document")

    if not file or not file.filename:
        return "Please select a document.", 400

    if not allowed_file(file.filename):
        return "File type not allowed.", 400

    filename = secure_filename(file.filename)
    if not filename:
        return "Invalid filename.", 400

    saved_name = os.urandom(16).hex() + "_" + filename
    file.save(os.path.join(UPLOAD_FOLDER, saved_name))

    with sqlite3.connect("trustvault.db") as con:
        con.execute(
            "INSERT INTO documents (filename, owner) VALUES (?, ?)",
            (filename, session["username"])
        )

    return redirect("/dashboard")

@app.route("/share", methods=["POST"])
def share():
    if "username" not in session:
        return redirect("/")

    if session["role"] != "Owner":
        return "Access denied.", 403

    document_id = request.form["document_id"]
    shared_with = request.form["shared_with"].strip()

    with sqlite3.connect("trustvault.db") as con:
        document = con.execute(
            "SELECT id FROM documents WHERE id = ? AND owner = ?",
            (document_id, session["username"])
        ).fetchone()

        user = con.execute(
            "SELECT username FROM users WHERE username = ?",
            (shared_with,)
        ).fetchone()

        if not document:
            return "Document not found or not owned by you.", 404

        if not user:
            return "That username does not exist.", 404

        if shared_with == session["username"]:
            return "You already own this document.", 400

        try:
            con.execute(
                "INSERT INTO document_shares (document_id, shared_with) VALUES (?, ?)",
                (document_id, shared_with)
            )
        except sqlite3.IntegrityError:
            return "This document is already shared with that user."

    return "Document shared successfully! <a href='/dashboard'>Back to dashboard</a>"


@app.route("/revoke", methods=["POST"])
def revoke_access():
    if "username" not in session:
        return redirect("/")

    if session.get("role") != "Owner":
        abort(403)

    document_id = request.form.get("document_id", type=int)
    target_username = request.form.get("username", "").strip()
    owner = session["username"]

    if not document_id or not target_username:
        return "Document ID and username are required.", 400

    with sqlite3.connect("trustvault.db") as con:
        document = con.execute(
            "SELECT id FROM documents WHERE id = ? AND owner = ?",
            (document_id, owner)
        ).fetchone()

        if not document:
            abort(403)

        result = con.execute(
            "DELETE FROM document_shares WHERE document_id = ? AND shared_with = ?",
            (document_id, target_username)
        )

    if result.rowcount == 0:
        return "No matching share found for that viewer.", 404

    return redirect("/dashboard")


@app.route("/document/<int:document_id>")
def view_document(document_id):
    if "username" not in session:
        return redirect("/")

    username = session["username"]

    with sqlite3.connect("trustvault.db") as con:
        document = con.execute(
            "SELECT id, filename, owner FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if not document:
            con.execute(
                "INSERT INTO activity_logs (username, action, document_id) VALUES (?, ?, ?)",
                (username, "Access denied - document not found", document_id)
            )
            abort(404)

        owner = document[2]

        shared = con.execute(
            """SELECT 1 FROM document_shares
               WHERE document_id = ? AND shared_with = ?""",
            (document_id, username)
        ).fetchone()

        if owner != username and not shared:
            con.execute(
                "INSERT INTO activity_logs (username, action, document_id) VALUES (?, ?, ?)",
                (username, "Access denied", document_id)
            )
            con.commit()
            abort(403)

        con.execute(
            "INSERT INTO activity_logs (username, action, document_id) VALUES (?, ?, ?)",
            (username, "Document accessed", document_id)
        )

    stored_file = None
    expected_suffix = "_" + secure_filename(document[1])

    with os.scandir(UPLOAD_FOLDER) as entries:
        for entry in entries:
            if entry.is_file() and entry.name.endswith(expected_suffix):
                stored_file = entry.name
                break

    if not stored_file:
        abort(404)

    return send_from_directory(
        UPLOAD_FOLDER, stored_file, as_attachment=True
    )

@app.route("/admin")
def admin_dashboard():
    if "username" not in session:
        return redirect("/")

    if session.get("role") != "Admin":
        abort(403)

    with sqlite3.connect("trustvault.db") as con:
        logs = con.execute(
            """SELECT username, action, document_id, timestamp
               FROM activity_logs
               ORDER BY id DESC"""
        ).fetchall()

    return render_template("admin.html", logs=logs)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
