print("=== MailNotifier API v3.0 - MONITOR ACTIF ===")
import os
import re
import time
import random
import smtplib
import imaplib
import email as _email_lib
import requests
import hashlib
import threading
import json as _json
from ssl import create_default_context
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header as _decode_header
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
import psycopg2.pool
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max request body

# CORS restreint aux origines connues
ALLOWED_ORIGINS = [
    "https://yanixx35.github.io",
    "https://bs-mailnotif-nine.vercel.app",
    "http://localhost:4200",
    "http://localhost:4201",
]
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

# Rate limiting (mémoire locale — réinitialisé au redémarrage)
# Désactivé en environnement de test (TESTING=1) pour éviter les conflits avec threading mocks
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
    enabled=not bool(os.getenv('TESTING')),
)

@app.after_request
def add_security_headers(response):
    origin = request.headers.get('Origin', '')
    
    # CORS : Autoriser explicitement l'origin Vercel
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        # Pour le développement, autoriser toutes les origins (à commenter en prod)
        response.headers['Access-Control-Allow-Origin'] = '*'
    
    # Headers CORS complets
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Cache-Control, Pragma, X-Requested-With'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
    response.headers['Access-Control-Max-Age'] = '86400'  # 24 heures
    
    # Headers de sécurité
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    """Gère les requêtes preflight OPTIONS avec tous les headers CORS nécessaires"""
    response = ''
    # Si c'est une requête preflight, renvoyer les headers CORS
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '')
        if origin in ALLOWED_ORIGINS:
            response = jsonify({'status': 'preflight'})
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Cache-Control, Pragma, X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Max-Age'] = '86400'
    return response, 200

SMTP_EMAIL        = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD     = os.getenv('SMTP_PASSWORD')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

notifier_status = {"running": False}


# ─── TELEGRAM BOT POLLING ─────────────────────────────────────────────────────

def telegram_bot_polling():
    """Ecoute les messages Telegram et repond au /start avec le Chat ID."""
    if not TELEGRAM_BOT_TOKEN:
        return
    offset = None
    print("[TelegramBot] Demarrage du polling...")
    while True:
        try:
            params = {"timeout": 30, "allowed_updates": ["message"]}
            if offset:
                params["offset"] = offset
            resp = requests.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                params=params, timeout=35
            )
            if not resp.ok:
                time.sleep(5)
                continue
            updates = resp.json().get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                text = msg.get("text", "")
                chat_id = msg.get("chat", {}).get("id")
                if chat_id and text.startswith("/start"):
                    reply = (
                        f"Bonjour ! Je suis le bot MailNotifier.\n\n"
                        f"Ton Telegram Chat ID est :\n"
                        f"<code>{chat_id}</code>\n\n"
                        f"Copie ce numero et colle-le dans les parametres de ton dashboard pour activer les notifications."
                    )
                    requests.post(
                        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                        json={"chat_id": chat_id, "text": reply, "parse_mode": "HTML"},
                        timeout=10
                    )
        except Exception as e:
            print(f"[TelegramBot] Erreur: {e}")
            time.sleep(5)


# ─── DATABASE ─────────────────────────────────────────────────────────────────

_DB_PARAMS = dict(
    host=os.getenv('DB_HOST'),
    port=int(os.getenv('DB_PORT', 5432)),
    user=os.getenv('DB_USER', 'avnadmin'),
    password=os.getenv('DB_PASSWORD'),
    dbname=os.getenv('DB_NAME', 'defaultdb'),
    sslmode='require',
    connect_timeout=10,
    cursor_factory=psycopg2.extras.RealDictCursor,
)

# Connexion pool — 2 min, 10 max (Render free tier: max 25 connexions)
_db_pool = None

def _get_pool():
    global _db_pool
    if _db_pool is None:
        _db_pool = psycopg2.pool.ThreadedConnectionPool(2, 10, **_DB_PARAMS)
    return _db_pool

def get_db():
    """Retourne une connexion depuis le pool (à rendre avec _return_db(db))."""
    try:
        return _get_pool().getconn()
    except Exception:
        # Fallback direct si le pool n'est pas disponible (e.g. tests)
        return psycopg2.connect(**_DB_PARAMS)

def _return_db(conn):
    """Remet la connexion dans le pool plutôt que de la fermer."""
    try:
        pool = _get_pool()
        pool.putconn(conn)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass

def init_db():
    """Crée les tables si elles n'existent pas."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(150) NOT NULL UNIQUE,
                    password VARCHAR(64) NOT NULL,
                    is_verified SMALLINT DEFAULT 1,
                    role VARCHAR(20) DEFAULT 'user',
                    plan VARCHAR(20) DEFAULT 'free',
                    phone VARCHAR(30),
                    gmail_address VARCHAR(150),
                    telegram_chat_id VARCHAR(50),
                    green_api_instance VARCHAR(100),
                    green_api_token VARCHAR(100),
                    gmail_token TEXT,
                    last_history_id VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_token TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_history_id VARCHAR(50)")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS app_password VARCHAR(200)")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_color VARCHAR(20)")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS font_family VARCHAR(60)")
            # Promouvoir l'admin principal
            cur.execute("UPDATE users SET role='admin' WHERE email='kyliyanisse@gmail.com'")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS otp_codes (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(150) NOT NULL,
                    code VARCHAR(6) NOT NULL,
                    name VARCHAR(100),
                    password VARCHAR(64),
                    extra TEXT,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS payments (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL,
                    plan VARCHAR(20),
                    amount DECIMAL(10,2),
                    status VARCHAR(20) DEFAULT 'paid',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        db.commit()
        print("Tables verifiees/creees avec succes.")
    finally:
        _return_db(db)




# ─── UTILS ────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hache le mot de passe avec bcrypt (coût 12)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Vérifie le mot de passe contre le hash stocké.
    Gère la migration transparente : anciens comptes SHA256 → bcrypt.
    """
    try:
        # Nouveau format : hash bcrypt ($2b$...)
        if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        # Ancien format : SHA256 hexdigest (64 chars hex)
        import hashlib
        return stored_hash == hashlib.sha256(password.encode()).hexdigest()
    except Exception:
        return False

# ─── VALIDATION ───────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

def _is_valid_email(value: str) -> bool:
    return bool(value and _EMAIL_RE.match(value) and len(value) <= 150)

def _check_password(password) -> str | None:
    """Returns error message if invalid, None if ok."""
    if not password or not isinstance(password, str):
        return 'Mot de passe requis'
    if len(password) < 8:
        return 'Mot de passe trop court (minimum 8 caractères)'
    if len(password) > 128:
        return 'Mot de passe trop long (maximum 128 caractères)'
    return None

def _str(value, max_len: int = 200) -> str:
    """Safely coerce a field to string, strip whitespace, truncate."""
    return str(value or '').strip()[:max_len]


def send_otp_email(to_email, name, otp_code, is_reset=False):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = (
            f'Votre code de réinitialisation MailNotifier : {otp_code}'
            if is_reset else
            f'Votre code de verification MailNotifier : {otp_code}'
        )
        msg['From'] = SMTP_EMAIL
        msg['To']   = to_email

        title_text       = "Réinitialisation de votre mot de passe" if is_reset else "Verification de votre compte"
        instruction_text = "Voici votre code de réinitialisation :" if is_reset else "Voici votre code de verification :"

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f5f5f5;border-radius:16px;">
          <div style="text-align:center;margin-bottom:24px;">
            <h1 style="color:#1a237e;margin:0;">MailNotifier</h1>
            <p style="color:#666;margin:4px 0;">{title_text}</p>
          </div>
          <div style="background:white;border-radius:12px;padding:32px;text-align:center;">
            <p style="color:#333;font-size:16px;">Bonjour <strong>{name}</strong>,</p>
            <p style="color:#555;font-size:14px;">{instruction_text}</p>
            <div style="background:#e8eaf6;border-radius:12px;padding:24px;margin:24px 0;">
              <span style="font-size:42px;font-weight:900;letter-spacing:12px;color:#1a237e;">{otp_code}</span>
            </div>
            <p style="color:#888;font-size:13px;">Ce code expire dans <strong>15 minutes</strong>.</p>
            <p style="color:#bbb;font-size:12px;">Si vous n'avez pas fait cette demande, ignorez cet email.</p>
          </div>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))

        ctx = create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=ctx) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print(f"[SMTP] Email envoyé à {to_email}")

    except Exception as e:
        print(f"[SMTP ERROR] Échec envoi à {to_email}: {type(e).__name__}")
        raise e


# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Corps JSON requis'}), 400

    name           = _str(data.get('name'), 100)
    email          = _str(data.get('email'), 150).lower()
    password       = data.get('password')
    phone          = _str(data.get('phone'), 30)
    gmail_address  = _str(data.get('gmail_address'), 150).lower()
    telegram_chat_id   = _str(data.get('telegram_chat_id'), 50)
    green_api_instance = _str(data.get('green_api_instance'), 100)
    green_api_token    = _str(data.get('green_api_token'), 100)

    if not name:
        return jsonify({'error': 'Nom requis'}), 400
    if not _is_valid_email(email):
        return jsonify({'error': 'Adresse email invalide'}), 400
    pw_error = _check_password(password)
    if pw_error:
        return jsonify({'error': pw_error}), 400
    password = str(password)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({'error': 'Cet email est deja utilise'}), 409

            cur.execute("DELETE FROM otp_codes WHERE email = %s", (email,))

            otp_code   = str(random.randint(100000, 999999))
            expires_at = datetime.now() + timedelta(minutes=10)

            # Stocker toutes les infos dans otp_codes (JSON extra)
            import json as _json
            extra = _json.dumps({
                'phone': phone,
                'gmail_address': gmail_address or email,
                'telegram_chat_id': telegram_chat_id,
                'green_api_instance': green_api_instance,
                'green_api_token': green_api_token
            })

            cur.execute(
                "INSERT INTO otp_codes (email, code, name, password, expires_at, extra) VALUES (%s,%s,%s,%s,%s,%s)",
                (email, otp_code, name, hash_password(password), expires_at, extra)
            )
        db.commit()
    finally:
        _return_db(db)

    def send_async():
        try:
            send_otp_email(email, name, otp_code)
        except Exception as e:
            print(f"[SMTP ERREUR] {e}")

    threading.Thread(target=send_async, daemon=True).start()
    return jsonify({'message': f'Code OTP envoye a {email}'}), 200


@app.route('/api/auth/verify-otp', methods=['POST'])
@limiter.limit("10 per minute")
def verify_otp():
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Corps JSON requis'}), 400

    email = _str(data.get('email'), 150).lower()
    code  = _str(data.get('code'), 6)

    if not _is_valid_email(email):
        return jsonify({'error': 'Adresse email invalide'}), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({'error': 'Code OTP invalide (6 chiffres attendus)'}), 400

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM otp_codes WHERE email = %s ORDER BY created_at DESC LIMIT 1",
                (email,)
            )
            otp = cur.fetchone()

            if not otp:
                return jsonify({'error': 'Aucun OTP en attente pour cet email'}), 404

            if datetime.now() > otp['expires_at']:
                cur.execute("DELETE FROM otp_codes WHERE email = %s", (email,))
                db.commit()
                return jsonify({'error': 'Code OTP expire, recommencez'}), 410

            if otp['code'] != code:
                return jsonify({'error': 'Code incorrect'}), 401

            # Récupérer les infos supplémentaires
            import json as _json
            extra = {}
            if otp.get('extra'):
                try:
                    extra = _json.loads(otp['extra'])
                except:
                    extra = {}

            cur.execute(
                """INSERT INTO users
                   (name, email, password, is_verified, phone, gmail_address,
                    telegram_chat_id, green_api_instance, green_api_token)
                   VALUES (%s,%s,%s,1,%s,%s,%s,%s,%s)""",
                (
                    otp['name'], email, otp['password'],
                    extra.get('phone'),
                    extra.get('gmail_address', email),
                    extra.get('telegram_chat_id'),
                    extra.get('green_api_instance'),
                    extra.get('green_api_token')
                )
            )
            cur.execute("DELETE FROM otp_codes WHERE email = %s", (email,))
            db.commit()

            return jsonify({'message': 'Compte cree avec succes !', 'name': otp['name']}), 201
    finally:
        _return_db(db)


@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    """Génère un code OTP pour la réinitialisation du mot de passe."""
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Corps JSON requis'}), 400

    email = _str(data.get('email'), 150).lower()
    if not _is_valid_email(email):
        return jsonify({'error': 'Adresse email invalide'}), 400

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return jsonify({'error': 'Configuration SMTP manquante'}), 500

    db = None
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, name FROM users WHERE email = %s AND is_verified = 1", (email,))
            user = cur.fetchone()

            if not user:
                # Réponse générique pour éviter l'énumération d'emails
                return jsonify({'message': 'Si cet email existe, un code vous a été envoyé'}), 200

            user_name = user.get('name', '')
            otp = str(random.randint(100000, 999999))
            expires_at = datetime.now() + timedelta(minutes=15)

            cur.execute("DELETE FROM otp_codes WHERE email = %s", (email,))
            cur.execute(
                "INSERT INTO otp_codes (email, code, name, expires_at) VALUES (%s, %s, %s, %s)",
                (email, otp, user_name, expires_at)
            )
            db.commit()

            try:
                send_otp_email(email, user_name, otp, is_reset=True)
            except Exception as email_error:
                print(f"[ERROR] Email sending failed: {email_error}")

            return jsonify({'message': 'Si cet email existe, un code vous a été envoyé'}), 200

    except psycopg2.Error:
        return jsonify({'error': 'Erreur base de données'}), 500
    except Exception as e:
        print(f"[ERROR] ForgotPassword: {e}")
        return jsonify({'error': 'Erreur technique'}), 500
    finally:
        if db:
            _return_db(db)


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Réinitialise le mot de passe avec le code OTP."""
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Corps JSON requis'}), 400

    email        = _str(data.get('email'), 150).lower()
    code         = _str(data.get('code'), 6)
    new_password = data.get('newPassword') or data.get('new_password')

    if not _is_valid_email(email):
        return jsonify({'error': 'Adresse email invalide'}), 400
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({'error': 'Code de réinitialisation invalide'}), 400
    pw_error = _check_password(new_password)
    if pw_error:
        return jsonify({'error': pw_error}), 400
    new_password = str(new_password)
    
    db = None
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT id FROM otp_codes
                WHERE email = %s AND code = %s AND expires_at > NOW()
            """, (email, code))
            if not cur.fetchone():
                return jsonify({'error': 'Code invalide ou expiré'}), 400

            cur.execute("""
                UPDATE users SET password = %s
                WHERE email = %s AND is_verified = 1
            """, (hash_password(new_password), email))
            cur.execute("DELETE FROM otp_codes WHERE email = %s", (email,))
            db.commit()

        return jsonify({'message': 'Mot de passe réinitialisé avec succès'}), 200

    except Exception as e:
        print(f"[ResetPassword] Error: {e}")
        return jsonify({'error': 'Erreur lors de la réinitialisation'}), 500
    finally:
        if db:
            _return_db(db)


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Corps JSON requis'}), 400

    email    = _str(data.get('email'), 150).lower()
    password = data.get('password')

    # 400 for genuinely missing fields (form UX)
    if not email:
        return jsonify({'error': 'Email requis'}), 400
    if not password or not isinstance(password, str) or not str(password).strip():
        return jsonify({'error': 'Mot de passe requis'}), 400

    # Invalid email format or oversized → generic 401 (no enumeration info)
    if not _is_valid_email(email) or len(str(password)) > 128:
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

        if not user:
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
        
        if not verify_password(password, user['password']):
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

        # Migration transparente : re-hasher les anciens comptes SHA256 vers bcrypt
        if not (user['password'].startswith('$2b$') or user['password'].startswith('$2a$')):
            new_hash = hash_password(password)
            with db.cursor() as cur:
                cur.execute("UPDATE users SET password = %s WHERE email = %s", (new_hash, email))
            db.commit()

        return jsonify({
            'message': 'Connexion reussie',
            'name': user['name'],
            'email': email,
            'role': user.get('role', 'user')
        }), 200
    finally:
        _return_db(db)


# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/api/admin/stats')
def admin_stats():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM users")
            total_users = cur.fetchone()['total']
            cur.execute("SELECT COUNT(*) as total FROM users WHERE role='admin'")
            total_admins = cur.fetchone()['total']
            cur.execute("SELECT COUNT(*) as total FROM users WHERE is_verified=1")
            verified = cur.fetchone()['total']
            cur.execute("SELECT COUNT(*) as total FROM users WHERE plan='premium'")
            premium = cur.fetchone()['total']
            cur.execute("SELECT COUNT(*) as total FROM payments WHERE status='paid'")
            total_payments = cur.fetchone()['total'] if True else 0
            cur.execute("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='paid'")
            revenue = cur.fetchone()['total']
        return jsonify({
            "total_users": total_users,
            "total_admins": total_admins,
            "verified_users": verified,
            "premium_users": premium,
            "total_payments": total_payments,
            "total_revenue": float(revenue)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        _return_db(db)


@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, name, email, is_verified, role, plan, phone,
                       gmail_address, telegram_chat_id, green_api_instance,
                       CASE WHEN app_password IS NOT NULL THEN TRUE ELSE FALSE END as gmail_connected,
                       CASE WHEN last_history_id IS NOT NULL THEN TRUE ELSE FALSE END as monitor_active,
                       created_at
                FROM users ORDER BY created_at DESC
            """)
            rows = cur.fetchall()
            users = []
            for u in rows:
                u = dict(u)
                if u.get('created_at'):
                    u['created_at'] = u['created_at'].strftime('%Y-%m-%d %H:%M')
                users.append(u)
        return jsonify(users), 200
    finally:
        _return_db(db)


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def admin_update_user(user_id):
    data = request.json
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE users SET name=%s, email=%s, role=%s, plan=%s, is_verified=%s WHERE id=%s",
                (data.get('name'), data.get('email'), data.get('role','user'),
                 data.get('plan','free'), data.get('is_verified',1), user_id)
            )
        db.commit()
        return jsonify({'message': 'Utilisateur mis a jour'}), 200
    finally:
        _return_db(db)


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        return jsonify({'message': 'Utilisateur supprime'}), 200
    finally:
        _return_db(db)


@app.route('/api/admin/users', methods=['POST'])
def admin_create_user():
    data = request.json
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (name, email, password, is_verified, role, plan) VALUES (%s,%s,%s,1,%s,%s)",
                (data['name'], data['email'], hash_password(data.get('password','123456')),
                 data.get('role','user'), data.get('plan','free'))
            )
        db.commit()
        return jsonify({'message': 'Utilisateur cree'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        _return_db(db)


@app.route('/api/admin/payments', methods=['GET'])
def admin_get_payments():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT p.id, u.name, u.email, p.plan, p.amount, p.status, p.created_at
                FROM payments p JOIN users u ON p.user_id=u.id
                ORDER BY p.created_at DESC
            """)
            rows = cur.fetchall()
            payments = []
            for p in rows:
                p = dict(p)
                if p.get('created_at'):
                    p['created_at'] = p['created_at'].strftime('%Y-%m-%d %H:%M')
                p['amount'] = float(p['amount'])
                payments.append(p)
        return jsonify(payments), 200
    except:
        return jsonify([]), 200
    finally:
        _return_db(db)


@app.route('/api/admin/payments', methods=['POST'])
def admin_create_payment():
    data = request.json
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO payments (user_id, plan, amount, status) VALUES (%s,%s,%s,%s)",
                (data['user_id'], data['plan'], data['amount'], data.get('status','paid'))
            )
            cur.execute("UPDATE users SET plan=%s WHERE id=%s", (data['plan'], data['user_id']))
        db.commit()
        return jsonify({'message': 'Paiement enregistre'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        _return_db(db)


@app.route('/api/admin/payments/<int:pay_id>', methods=['DELETE'])
def admin_delete_payment(pay_id):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM payments WHERE id=%s", (pay_id,))
        db.commit()
        return jsonify({'message': 'Paiement supprime'}), 200
    finally:
        _return_db(db)


# ─── GMAIL IMAP ───────────────────────────────────────────────────────────────

@app.route('/api/auth/gmail-test', methods=['POST'])
def test_gmail_imap():
    """Teste la connexion IMAP Gmail avec un mot de passe d'application."""
    data   = request.get_json() or {}
    gmail  = data.get('gmail_address', '').strip().lower()
    passwd = data.get('app_password', '').replace(' ', '').strip()
    if not gmail or not passwd:
        return jsonify({'success': False, 'error': 'Adresse Gmail et mot de passe requis'}), 400
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(gmail, passwd)
        mail.logout()
        return jsonify({'success': True})
    except imaplib.IMAP4.error:
        return jsonify({'success': False, 'error': 'Code incorrect ou IMAP desactive'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/auth/gmail-status')
def gmail_status():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'connected': False}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT app_password FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
        return jsonify({'connected': bool(user and user.get('app_password'))})
    finally:
        _return_db(db)


@app.route('/api/status')
def get_status():
    return jsonify({
        "running": notifier_status["running"],
        "email": os.getenv('GMAIL_ADDRESS'),
        "telegram": True,
        "whatsapp": True
    })


# Cache des connexions IMAP : {email: (imap_conn, timestamp)}
_imap_cache: dict = {}
_IMAP_TTL = 60  # secondes

def _get_imap_conn(email_addr):
    """
    Retourne une connexion IMAP4_SSL pour l'utilisateur.
    Réutilise la connexion si elle date de moins de 60s, sinon en crée une nouvelle.
    """
    cached = _imap_cache.get(email_addr)
    if cached:
        conn, ts = cached
        if time.time() - ts < _IMAP_TTL:
            try:
                conn.noop()  # vérifie que la connexion est toujours vivante
                return conn
            except Exception:
                _imap_cache.pop(email_addr, None)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT app_password FROM users WHERE email = %s AND is_verified = 1", (email_addr,))
            row = cur.fetchone()
    finally:
        _return_db(db)

    if not row or not row.get('app_password'):
        return None
    passwd = row['app_password'].replace(' ', '').strip()
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(email_addr, passwd)
        _imap_cache[email_addr] = (mail, time.time())
        return mail
    except Exception:
        return None


def _decode_mime_header(value):
    parts = _decode_header(value or '')
    result = []
    for part, enc in parts:
        if isinstance(part, bytes):
            result.append(part.decode(enc or 'utf-8', errors='replace'))
        else:
            result.append(part)
    return ''.join(result)


@app.route('/api/emails')
def get_emails():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify([])

    # Pagination : ?page=1&limit=20 (max 50 par page)
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(50, max(1, int(request.args.get('limit', 20))))
    except (ValueError, TypeError):
        page, limit = 1, 20

    try:
        mail = _get_imap_conn(email)
        if not mail:
            return jsonify([])
        mail.select('INBOX', readonly=True)
        _, data = mail.uid('search', None, 'ALL')
        all_uids = data[0].split()[::-1] if data[0] else []  # plus récents en premier

        total  = len(all_uids)
        start  = (page - 1) * limit
        uids   = all_uids[start:start + limit]

        emails = []
        for uid in uids:
            _, msg_data = mail.uid('fetch', uid, '(RFC822)')
            raw = msg_data[0][1]
            msg = _email_lib.message_from_bytes(raw)
            subject = _decode_mime_header(msg.get('Subject', '(Sans objet)'))
            sender  = _decode_mime_header(msg.get('From', 'Inconnu'))
            date    = msg.get('Date', '')
            body    = ''
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace')[:150]
                        break
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='replace')[:150]
            _, flags_data = mail.uid('fetch', uid, '(FLAGS)')
            is_unread = b'\\Seen' not in (flags_data[0] or b'')
            emails.append({
                "id": uid.decode(), "subject": subject, "sender": sender,
                "date": date, "snippet": body, "unread": is_unread
            })

        return jsonify({
            "emails": emails,
            "page": page,
            "limit": limit,
            "total": total,
            "pages": max(1, (total + limit - 1) // limit)
        })
    except Exception as e:
        print(f"[ERROR] get_emails: {e}")
        return jsonify({"error": "Erreur lors de la récupération des emails"}), 500


@app.route('/api/stats')
def get_stats():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({"total_messages": 0, "unread_count": 0, "email": email})
    try:
        mail = _get_imap_conn(email)
        if not mail:
            return jsonify({"total_messages": 0, "unread_count": 0, "email": email})
        mail.select('INBOX', readonly=True)
        _, total_data  = mail.uid('search', None, 'ALL')
        _, unread_data = mail.uid('search', None, 'UNSEEN')
        total  = len(total_data[0].split()) if total_data[0] else 0
        unread = len(unread_data[0].split()) if unread_data[0] else 0
        mail.logout()
        return jsonify({"total_messages": total, "unread_count": unread, "email": email})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── USER SETTINGS ────────────────────────────────────────────────────────────

@app.route('/api/user/whatsapp-qr', methods=['GET'])
def get_whatsapp_qr():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "email requis"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT green_api_instance, green_api_token FROM users WHERE email = %s AND is_verified = 1",
                (email,)
            )
            user = cur.fetchone()
        if not user or not user.get('green_api_instance') or not user.get('green_api_token'):
            return jsonify({"error": "Green API non configure pour cet utilisateur"}), 400
        instance = user['green_api_instance']
        token = user['green_api_token']
        url = f"https://api.green-api.com/waInstance{instance}/qr/{token}"
        resp = requests.get(url, timeout=15)
        if not resp.ok:
            return jsonify({"error": f"Erreur Green API: {resp.status_code}"}), 502
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        _return_db(db)


@app.route('/api/user/settings', methods=['GET'])
def get_user_settings():
    email = _str(request.args.get('email'), 150).lower()
    if not _is_valid_email(email):
        return jsonify({"error": "email requis"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT name, email, phone, gmail_address, telegram_chat_id, green_api_instance, "
                "green_api_token, app_password, avatar, theme_color, font_family "
                "FROM users WHERE email = %s AND is_verified = 1",
                (email,)
            )
            user = cur.fetchone()
        if not user:
            return jsonify({
                "name": "", "email": email, "phone": "",
                "gmail_address": "", "telegram_chat_id": "",
                "green_api_instance": "", "green_api_token": "",
                "app_password_set": False, "avatar": "",
                "theme_color": "", "font_family": ""
            })
        user = dict(user)
        for key in ["phone", "gmail_address", "telegram_chat_id", "green_api_instance",
                    "green_api_token", "avatar", "theme_color", "font_family"]:
            if user.get(key) is None:
                user[key] = ""
        user['app_password_set'] = bool(user.pop('app_password', None))
        return jsonify(user)
    finally:
        _return_db(db)


@app.route('/api/user/settings', methods=['PUT'])
def update_user_settings():
    data = request.get_json() or {}
    email = _str(data.get('email'), 150).lower()
    if not _is_valid_email(email):
        return jsonify({"error": "email requis"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            app_password = (_str(data.get('app_password'), 200).replace(' ', '') or None)
            avatar      = _str(data.get('avatar'), 65535) or None   # base64 image
            name        = _str(data.get('name'), 100) or None
            theme_color = _str(data.get('theme_color'), 20) or None
            font_family = _str(data.get('font_family'), 60) or None
            if app_password:
                cur.execute(
                    """UPDATE users SET
                        name = COALESCE(%s, name),
                        phone = %s,
                        gmail_address = %s,
                        telegram_chat_id = %s,
                        green_api_instance = %s,
                        green_api_token = %s,
                        app_password = %s,
                        avatar = COALESCE(%s, avatar),
                        theme_color = COALESCE(%s, theme_color),
                        font_family = COALESCE(%s, font_family)
                    WHERE email = %s AND is_verified = 1""",
                    (name, data.get('phone'), data.get('gmail_address'),
                     data.get('telegram_chat_id'), data.get('green_api_instance'),
                     data.get('green_api_token'), app_password,
                     avatar, theme_color, font_family, email)
                )
            else:
                cur.execute(
                    """UPDATE users SET
                        name = COALESCE(%s, name),
                        phone = %s,
                        gmail_address = %s,
                        telegram_chat_id = %s,
                        green_api_instance = %s,
                        green_api_token = %s,
                        avatar = COALESCE(%s, avatar),
                        theme_color = COALESCE(%s, theme_color),
                        font_family = COALESCE(%s, font_family)
                    WHERE email = %s AND is_verified = 1""",
                    (name, data.get('phone'), data.get('gmail_address'),
                     data.get('telegram_chat_id'), data.get('green_api_instance'),
                     data.get('green_api_token'),
                     avatar, theme_color, font_family, email)
                )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] update_user_settings: {e}")
        return jsonify({"error": "Erreur lors de la mise à jour"}), 500
    finally:
        _return_db(db)


# ─── EMAIL MONITOR ────────────────────────────────────────────────────────────

def _send_telegram_notification(chat_id, sender, subject, snippet, user_email):
    if not TELEGRAM_BOT_TOKEN:
        print("[Monitor] TELEGRAM_BOT_TOKEN manquant — notification ignoree")
        return
    match = re.match(r'^(.+?)\s*<', sender)
    sender_name = match.group(1).strip().strip('"') if match else sender.split('@')[0]
    text = (
        f"\U0001f4e7 *Nouveau mail recu !*\n\n"
        f"*De :* {sender_name}\n"
        f"*Objet :* {subject}\n"
        f"*Apercu :* {snippet}\n\n"
        f"_Compte : {user_email}_"
    )
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10
        )
        if resp.ok:
            print(f"[Monitor] Telegram OK -> chat_id={chat_id} pour {user_email}")
        else:
            print(f"[Monitor] Telegram erreur: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        print(f"[Monitor] Telegram exception: {e}")


def _save_last_uid(user_id, uid):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET last_history_id=%s WHERE id=%s", (str(uid), user_id))
        db.commit()
    finally:
        _return_db(db)


def _check_user_emails_imap(user):
    """Vérifie les nouveaux mails d'un utilisateur via IMAP + App Password."""
    gmail   = (user.get('gmail_address') or '').strip()
    passwd  = (user.get('app_password') or '').replace(' ', '').strip()
    chat_id = user.get('telegram_chat_id')
    user_id = user['id']
    last_uid = user.get('last_history_id')

    if not gmail or not passwd:
        return

    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(gmail, passwd)
        mail.select('INBOX', readonly=True)

        _, data = mail.uid('search', None, 'ALL')
        all_uids = data[0].split() if data[0] else []
        if not all_uids:
            mail.logout()
            return

        latest_uid = all_uids[-1]

        if not last_uid:
            # Premier passage : on note le dernier UID sans notifier
            _save_last_uid(user_id, latest_uid.decode())
            print(f"[Monitor] Init last_uid={latest_uid.decode()} pour {gmail}")
            mail.logout()
            return

        # Cherche les UIDs plus récents que last_uid
        _, new_data = mail.uid('search', None, f'UID {int(last_uid)+1}:*')
        new_uids = new_data[0].split() if new_data[0] else []
        new_uids = [u for u in new_uids if int(u) > int(last_uid)]

        for uid in new_uids:
            try:
                _, msg_data = mail.uid('fetch', uid, '(RFC822)')
                raw = msg_data[0][1]
                msg = _email_lib.message_from_bytes(raw)
                subject = _decode_mime_header(msg.get('Subject', '(Sans objet)'))
                sender  = _decode_mime_header(msg.get('From', 'Inconnu'))
                body    = ''
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain':
                            body = part.get_payload(decode=True).decode('utf-8', errors='replace')[:200]
                            break
                else:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='replace')[:200]
                if chat_id:
                    _send_telegram_notification(chat_id, sender, subject, body, gmail)
            except Exception as e:
                print(f"[Monitor] Erreur lecture UID {uid}: {e}")

        _save_last_uid(user_id, latest_uid.decode())
        mail.logout()

    except imaplib.IMAP4.error as e:
        print(f"[Monitor] IMAP erreur pour {gmail}: {e}")
    except Exception as e:
        print(f"[Monitor] Erreur inattendue pour {gmail}: {e}")


def _check_all_users():
    """Récupère tous les utilisateurs surveillables et vérifie leurs mails via IMAP."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, email, gmail_address, app_password, telegram_chat_id, last_history_id
                FROM users
                WHERE app_password IS NOT NULL
                  AND gmail_address IS NOT NULL
                  AND gmail_address != ''
                  AND telegram_chat_id IS NOT NULL
                  AND telegram_chat_id != ''
                  AND is_verified = 1
            """)
            users = [dict(u) for u in cur.fetchall()]
    finally:
        _return_db(db)

    if not users:
        return

    print(f"[Monitor] Verification IMAP de {len(users)} utilisateur(s)...")
    for user in users:
        try:
            _check_user_emails_imap(user)
        except Exception as e:
            print(f"[Monitor] Erreur user {user['email']}: {e}")


def monitor_emails_loop():
    """Boucle principale : vérifie les nouveaux mails toutes les 30 secondes."""
    print("[Monitor] Surveillance des emails demarree (intervalle 30s)")
    while True:
        try:
            _check_all_users()
        except Exception as e:
            print(f"[Monitor] Erreur boucle: {e}")
        time.sleep(30)


# ─── DEBUG / TEST ENDPOINT ────────────────────────────────────────────────────

@app.route('/api/monitor/test', methods=['GET', 'POST'])
def monitor_test():
    """Endpoint de debug : liste les utilisateurs et leur etat IMAP."""
    logs = []

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, email, gmail_address, telegram_chat_id, last_history_id,
                       (app_password IS NOT NULL) as has_password
                FROM users WHERE is_verified = 1
            """)
            all_users = [dict(u) for u in cur.fetchall()]
    finally:
        _return_db(db)

    logs.append(f"Total utilisateurs: {len(all_users)}")
    for u in all_users:
        logs.append(
            f"  - {u['email']} | gmail={u['gmail_address']} | "
            f"app_password={'OUI' if u['has_password'] else 'NON'} | "
            f"telegram={u['telegram_chat_id']} | last_uid={u['last_history_id']}"
        )

    eligible = [u for u in all_users if u['has_password'] and u['telegram_chat_id']]
    logs.append(f"Eligibles IMAP (app_password + telegram): {len(eligible)}")

    for user in eligible:
        test_text = (
            f"\U0001f4e7 *Test MailNotifier*\n\n"
            f"Le systeme de notification IMAP fonctionne !\n"
            f"_Compte surveille : {user['gmail_address'] or user['email']}_"
        )
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": user['telegram_chat_id'], "text": test_text, "parse_mode": "Markdown"},
                timeout=10
            )
            if resp.ok:
                logs.append(f"  ✓ {user['email']}: message Telegram ENVOYE (chat_id={user['telegram_chat_id']})")
            else:
                logs.append(f"  ✗ {user['email']}: Telegram erreur {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logs.append(f"  ✗ {user['email']}: Telegram exception: {e}")

    return jsonify({"logs": logs, "token_ok": bool(TELEGRAM_BOT_TOKEN)}), 200


# ─── STARTUP (fonctionne avec gunicorn ET python api.py) ─────────────────────

def _startup():
    # Skip startup in test environment (avoids real DB connections and daemon threads)
    if os.getenv('TESTING'):
        return
    print("[STARTUP] Debut de l'initialisation...")
    try:
        init_db()
        notifier_status["running"] = True
        print("[STARTUP] Lancement thread TelegramBot...")
        threading.Thread(target=telegram_bot_polling, daemon=True, name="tg-bot").start()
        print("[STARTUP] Lancement thread email-monitor...")
        threading.Thread(target=monitor_emails_loop, daemon=True, name="email-monitor").start()
        print("[STARTUP] Tous les threads lances avec succes.")
    except Exception as e:
        import traceback
        print(f"[STARTUP] ERREUR CRITIQUE: {e}")
        traceback.print_exc()

_startup()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
