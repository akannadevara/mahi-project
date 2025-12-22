# app.py (full updated)
import os
import uuid
import json
import secrets
import string
import traceback
import mimetypes
import logging
from flask import (
    Flask, request, jsonify, session, send_file,
    render_template, render_template_string, url_for
)
import pymysql
pymysql.install_as_MySQLdb()

from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

# config
from config import Config

# ---------- app init ----------
app = Flask(__name__, template_folder='frontend/templates', static_folder='frontend/static')
app.config.from_object(Config)

# DEV: reduce static caching during development (avoid persistent 304s while debugging)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.info("Starting app.py: %s", os.path.abspath(__file__))

# session & CORS
app.secret_key = os.environ.get('SECRET_KEY', getattr(Config, 'SECRET_KEY', 'dev-secret-key'))
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/uploads/*": {"origins": "*"}}, supports_credentials=True)

# ---------- MAIL CONFIG (fixed & robust) ----------
# Use environment variables in production. Defaults are safe for dev.
# Important: MAIL_USERNAME should be your gmail address, MAIL_PASSWORD should be an App Password if using 2FA.
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', getattr(Config, 'MAIL_SERVER', 'akannadevara@gmail.com'))
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', getattr(Config, 'MAIL_PORT', 587)))
# Interpret TLS/SSL booleans robustly
app.config['MAIL_USE_TLS'] = str(os.getenv('MAIL_USE_TLS', str(getattr(Config, 'MAIL_USE_TLS', True)))).lower() in ('true', '1', 'yes')
app.config['MAIL_USE_SSL'] = str(os.getenv('MAIL_USE_SSL', str(getattr(Config, 'MAIL_USE_SSL', False)))).lower() in ('true', '1', 'yes')
# username/password from env or Config (no sensible default for password)
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', getattr(Config, 'MAIL_USERNAME', 'akannadevara@gmail.com'))
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', getattr(Config, 'MAIL_PASSWORD', 'qdmikwgdhrbtwmkd'))
# default sender should match the authenticated mail username to avoid rejection
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config.get('MAIL_USERNAME'))
# DEV helper: when True and mail fails we'll include debug details (set to False in production)
app.config['DEV_RETURN_EMAIL_DEBUG'] = os.getenv('DEV_RETURN_EMAIL_DEBUG', str(getattr(Config, 'DEV_RETURN_EMAIL_DEBUG', True))).lower() in ('true','1','yes')

# initialize Mail AFTER config is set
mail = Mail(app)

# ---------- uploads ----------
if not app.config.get('UPLOAD_FOLDER'):
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = os.path.abspath(app.config['UPLOAD_FOLDER'])
app.config['MAX_CONTENT_LENGTH'] = int(getattr(Config, 'MAX_CONTENT_LENGTH', 50 * 1024 * 1024))
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'photos'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'videos'), exist_ok=True)
app.logger.info("Upload folder: %s", app.config['UPLOAD_FOLDER'])

# ---------- try init flask_mysqldb ----------
mysql = None
try:
    mysql = MySQL(app)
    app.logger.info("Initialized flask_mysqldb extension")
except Exception:
    app.logger.exception("flask_mysqldb init failed; will attempt fallback connections")

# ---------- allowed extensions ----------
ALLOWED_PHOTO_EXT = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
ALLOWED_VIDEO_EXT = {'mp4', 'mov', 'avi', 'webm'}

_tokens = {}  # in-memory admin tokens (dev)

def allowed_file(filename, media_type):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if media_type == 'photo':
        return ext in ALLOWED_PHOTO_EXT
    return ext in ALLOWED_VIDEO_EXT

# ---------- admin storage ----------
ADMIN_STORE = os.path.join(os.path.dirname(__file__), 'admin.json')

def read_admin():
    if not os.path.exists(ADMIN_STORE):
        return None
    try:
        with open(ADMIN_STORE, 'r') as f:
            return json.load(f)
    except Exception:
        app.logger.exception("Failed to read admin.json")
        return None

def write_admin(email, password_hash):
    with open(ADMIN_STORE, 'w') as f:
        json.dump({"email": email, "password_hash": password_hash}, f)

def check_admin_credentials(username, password):
    admin = read_admin()
    if not admin:
        return False
    if username != admin.get('email'):
        return False
    return check_password_hash(admin.get('password_hash', ''), password)

def set_new_admin_password(new_password):
    admin = read_admin()
    if not admin:
        raise RuntimeError("No admin exists to change password for.")
    new_hash = generate_password_hash(new_password)
    write_admin(admin.get('email'), new_hash)

def _is_admin_request(req):
    if session.get('admin'):
        return True
    auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            return parts[1] in _tokens
    return False

# ------------------------
# DB helper with fallback
# ------------------------
_fallback_conn = None

def _create_fallback_connection():
    host = app.config.get('MYSQL_HOST') or os.getenv('MYSQL_HOST') or app.config.get('DB_HOST')
    user = app.config.get('MYSQL_USER') or os.getenv('MYSQL_USER') or app.config.get('DB_USER')
    password = app.config.get('MYSQL_PASSWORD') or os.getenv('MYSQL_PASSWORD') or app.config.get('DB_PASSWORD')
    db = app.config.get('MYSQL_DB') or os.getenv('MYSQL_DB') or app.config.get('DB_NAME')
    port = int(app.config.get('MYSQL_PORT') or os.getenv('MYSQL_PORT', 3306) or app.config.get('DB_PORT', 3306))

    if not (host and user and password and db):
        raise RuntimeError("MySQL config incomplete (check MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB or DB_* vars).")

    conn = pymysql.connect(
        host=host, user=user, password=password, db=db, port=port,
        charset='utf8mb4', cursorclass=pymysql.cursors.Cursor, autocommit=False, connect_timeout=10
    )
    return conn

def get_db_cursor():
    global _fallback_conn
    try:
        if mysql is not None:
            try:
                conn = mysql.connection
                if conn is not None:
                    cursor = conn.cursor()
                    return cursor, conn, None
            except Exception as e:
                app.logger.warning("flask_mysqldb connection attempt failed: %s", str(e))
    except Exception:
        app.logger.exception("Unexpected error while accessing flask_mysqldb")

    try:
        if _fallback_conn:
            try:
                _fallback_conn.ping(reconnect=True)
                cur = _fallback_conn.cursor()
                return cur, _fallback_conn, None
            except Exception:
                try:
                    _fallback_conn.close()
                except Exception:
                    pass
                _fallback_conn = None

        _fallback_conn = _create_fallback_connection()
        cur = _fallback_conn.cursor()
        app.logger.info("Using pymysql fallback connection (new)")
        return cur, _fallback_conn, None
    except Exception as e:
        app.logger.exception("Fallback pymysql connection failed")
        return None, None, f"DB connection error (flask_mysqldb and pymysql fallback failed): {str(e)}"

def _close_fallback_conn(conn_obj):
    global _fallback_conn
    try:
        conn_obj.close()
    except Exception:
        pass
    if _fallback_conn is conn_obj:
        _fallback_conn = None

# ------------------------
# Routes
# ------------------------
expected_index = os.path.join(
    app.root_path,
    'frontend',
    'templates',
    'index.html'
)


@app.route('/')
def index():
    if os.path.exists(expected_index):
        return render_template('index.html')
    return render_template_string("<h2>index.html not found</h2><p>Expected: {{expected}}</p>", expected=expected_index)

@app.route('/api/db-test')
def db_test():
    cursor, conn_obj, err = get_db_cursor()
    if err:
        return jsonify({"ok": False, "error": err}), 500
    try:
        cursor.execute("SELECT 1")
        try:
            cursor.close()
        except Exception:
            pass
        if conn_obj is not None and mysql is not None and conn_obj is not mysql.connection:
            _close_fallback_conn(conn_obj)
        return jsonify({"ok": True, "message": "DB connection OK"})
    except Exception as e:
        app.logger.exception("DB test query failed")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    admin = read_admin()
    if not admin:
        return jsonify({"success": False, "message": "No admin account exists. Create admin.json first."}), 401
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"success": False, "message": "Missing username or password"}), 400
    if check_admin_credentials(username, password):
        session['admin'] = True
        token = uuid.uuid4().hex
        _tokens[token] = True
        return jsonify({"success": True, "message": "Login successful", "token": token})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return jsonify({"success": True})

@app.route('/api/check-auth')
def check_auth():
    return jsonify({"authenticated": bool(_is_admin_request(request))})

# ------------------------
# Email: forgot-password (improved)
# ------------------------
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    admin = read_admin()
    if not admin:
        return jsonify({"success": False, "message": "No admin account exists. Create admin.json first."}), 404

    data = request.json or {}
    email = data.get('email')
    if email != admin.get('email'):
        return jsonify({"success": False, "message": "Email not found"}), 404

    alphabet = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(alphabet) for _ in range(12))

    try:
        set_new_admin_password(new_password)
    except Exception:
        app.logger.exception("Failed to write new admin password")
        return jsonify({"success": False, "message": "Server error saving new password."}), 500

    # Construct message
    msg = Message(
        subject='AVK Events Admin - Your new temporary password',
        sender=app.config.get('MAIL_DEFAULT_SENDER') or 'no-reply@example.com',
        recipients=[email]
    )
    msg.body = f"New password: {new_password}\nPlease change after login."

    mail_user = app.config.get('MAIL_USERNAME')
    mail_pw = app.config.get('MAIL_PASSWORD')

    # If MAIL not configured, fallback to returning password for local dev debugging
    if not mail_user or not mail_pw:
        app.logger.warning("Mail not configured - returning password in response (dev-only)")
        # Only return the password in dev mode; DO NOT do this in production
        return jsonify({"success": True, "message": "Mail not configured; use returned password (dev).", "password": new_password})

    # Attempt to send email and return any exception details (dev-only debug info)
    try:
        mail.send(msg)
        app.logger.info("Password reset email sent to %s", email)
        return jsonify({"success": True, "message": "A new password has been sent to your email. Check inbox/spam."})
    except Exception as e:
        app.logger.exception("Email send error")
        debug_info = str(e) if app.config.get('DEV_RETURN_EMAIL_DEBUG') else None
        resp = {"success": False, "message": "Failed to send email. See server logs for details."}
        if debug_info:
            resp['debug_error'] = debug_info
        # For convenience during dev include the password (remove this in production)
        if app.config.get('DEV_RETURN_EMAIL_DEBUG'):
            resp['password'] = new_password
        return jsonify(resp), 500

# Test endpoint to verify SMTP config quickly
@app.route('/api/test-email', methods=['POST'])
def test_email():
    """
    POST JSON: { "to": "you@example.com" }
    Returns SMTP error details (helpful for debugging).
    """
    target = (request.json or {}).get('to') or app.config.get('MAIL_USERNAME')
    if not target:
        return jsonify({"ok": False, "message": "No target email specified"}), 400

    msg = Message("AVK Events - test email", sender=app.config.get('MAIL_DEFAULT_SENDER'), recipients=[target])
    msg.body = "This is a test email to verify SMTP configuration."

    mail_user = app.config.get('MAIL_USERNAME')
    mail_pw = app.config.get('MAIL_PASSWORD')
    if not mail_user or not mail_pw:
        return jsonify({"ok": False, "message": "MAIL_USERNAME or MAIL_PASSWORD not configured in environment."}), 400

    try:
        mail.send(msg)
        app.logger.info("Test email sent to %s", target)
        return jsonify({"ok": True, "message": f"Test email sent to {target}"})
    except Exception as e:
        app.logger.exception("Test email failed")
        resp = {"ok": False, "error": "Failed to send test email."}
        if app.config.get('DEV_RETURN_EMAIL_DEBUG'):
            resp['debug'] = str(e)
        return jsonify(resp), 500

# Serve uploads safely
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    safe_path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    if not safe_path.startswith(app.config['UPLOAD_FOLDER']):
        return "Forbidden", 403
    if not os.path.exists(safe_path):
        return "Not Found", 404

    mime, _ = mimetypes.guess_type(safe_path)
    if not mime:
        mime = 'application/octet-stream'
    resp = send_file(safe_path, mimetype=mime, conditional=True)

    # DEV: disable caching for uploads while developing
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/api/media/<category>/<media_type>')
def get_media(category, media_type):
    valid_categories = ['marriage','haldi','engagement','birthday','reception','temple','home']
    if category not in valid_categories or media_type not in ['photos','videos']:
        return jsonify([])

    cursor, conn_obj, err = get_db_cursor()
    if err:
        app.logger.warning("get_media DB error: %s", err)
        return jsonify([])

    try:
        cursor.execute("SELECT file_path, type FROM media WHERE category=%s AND type=%s ORDER BY uploaded_at DESC",
                       (category, media_type[:-1]))
        rows = cursor.fetchall()
        try:
            cursor.close()
        except Exception:
            pass
        if conn_obj is not None and mysql is not None and conn_obj is not mysql.connection:
            _close_fallback_conn(conn_obj)
    except Exception:
        app.logger.exception("DB query error in get_media")
        return jsonify([]), 500

    items = []
    for r in rows:
        fp = r[0]
        typ = r[1] if len(r) > 1 else (media_type[:-1])
        try:
            url = url_for('uploaded_file', filename=fp, _external=False)
        except Exception:
            url = '/uploads/' + fp
        items.append({"type": typ, "url": url})
    return jsonify(items)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if not _is_admin_request(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file selected"}), 400
    file = request.files['file']
    category = request.form.get('category')
    media_type = request.form.get('type')
    valid_categories = ['marriage','haldi','engagement','birthday','reception','temple','home']
    if not category or category not in valid_categories:
        return jsonify({"success": False, "message": "Invalid category"}), 400
    if not media_type or media_type not in ['photo','video']:
        return jsonify({"success": False, "message": "Invalid media type"}), 400
    if file.filename == '':
        return jsonify({"success": False, "message": "No file selected"}), 400
    if not allowed_file(file.filename, media_type):
        return jsonify({"success": False, "message": "File type not allowed"}), 400

    try:
        file.stream.seek(0, os.SEEK_END)
        size = file.stream.tell()
        file.stream.seek(0)
    except Exception:
        size = getattr(file, 'content_length', None) or 0
    if size and size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({"success": False, "message": f"File too large. Max {app.config['MAX_CONTENT_LENGTH']} bytes"}), 400

    cursor, conn_obj, err = get_db_cursor()
    if err:
        return jsonify({"success": False, "message": err}), 500

    try:
        original = secure_filename(file.filename)
        ext = original.rsplit('.', 1)[1].lower() if '.' in original else ''
        filename = f"{uuid.uuid4().hex}.{ext}"
        folder = 'photos' if media_type == 'photo' else 'videos'
        rel_path = os.path.join(folder, filename).replace('\\','/')
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], rel_path)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        file.save(save_path)
        app.logger.info("Saved file to %s", save_path)
    except Exception as e:
        app.logger.exception("Failed to save uploaded file")
        return jsonify({"success": False, "message": f"Failed to save file: {str(e)}"}), 500

    try:
        cursor.execute("INSERT INTO media (category,type,file_path) VALUES (%s,%s,%s)", (category, media_type, rel_path))
        if conn_obj is not None and mysql is not None and conn_obj is not mysql.connection:
            conn_obj.commit()
            try:
                cursor.close()
            except Exception:
                pass
            _close_fallback_conn(conn_obj)
        else:
            try:
                mysql.connection.commit()
            except Exception:
                try:
                    if conn_obj is not None:
                        conn_obj.commit()
                except Exception:
                    pass
            try:
                cursor.close()
            except Exception:
                pass
    except Exception:
        app.logger.exception("DB insert failed; removing file")
        try:
            os.remove(save_path)
        except Exception:
            pass
        return jsonify({"success": False, "message": "Database error saving media record."}), 500

    try:
        file_url = url_for('uploaded_file', filename=rel_path, _external=False)
    except Exception:
        file_url = '/uploads/' + rel_path
    return jsonify({"success": True, "message": "Uploaded successfully", "url": file_url}), 200

# DEV: no-cache for certain paths to avoid stale 304s during development
@app.after_request
def set_dev_no_cache(response):
    try:
        p = request.path or ''
        if p.startswith('/static/') or p.startswith('/uploads/') or p.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
    except Exception:
        pass
    return response

if __name__ == '__main__':
    # For LAN testing: bind to all interfaces
    app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=bool(os.getenv('FLASK_DEBUG', '1') == '1'))
