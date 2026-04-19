print("=== MailNotifier API v4.1 - GMAIL OAUTH + FCM ===")
import os
import re
import time
import random
import smtplib
import requests
import hashlib
import threading
import json as _json
from ssl import create_default_context
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.errors import HttpError
from flask import Flask, jsonify, request, redirect, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
import psycopg2.pool
import bcrypt
import jwt
from functools import wraps
import firebase_admin
from firebase_admin import credentials as fb_credentials, messaging as fb_messaging

load_dotenv()

# ─── FIREBASE ADMIN INIT ──────────────────────────────────────────────────────
_firebase_initialized = False
def _init_firebase():
    global _firebase_initialized
    if _firebase_initialized:
        return
    cred_json = os.getenv('FIREBASE_CREDENTIALS_JSON')
    if not cred_json:
        print("[Firebase] FIREBASE_CREDENTIALS_JSON manquant — push notifications désactivées")
        return
    try:
        import json as _fbjson
        cred_dict = _fbjson.loads(cred_json)
        cred = fb_credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        print("[Firebase] Admin SDK initialisé avec succès")
    except Exception as e:
        print(f"[Firebase] Erreur initialisation: {e}")

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

# Initialiser SocketIO pour WebSocket avec les mêmes origines que CORS
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode='threading')

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
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Cache-Control, Pragma, X-Requested-With, Expires'
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
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Cache-Control, Pragma, X-Requested-With, Expires'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Max-Age'] = '86400'
    return response, 200

SMTP_EMAIL        = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD     = os.getenv('SMTP_PASSWORD')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
JWT_SECRET_KEY    = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
JWT_ALGORITHM     = 'HS256'

# ─── GOOGLE OAUTH CONFIG ──────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
OAUTH_REDIRECT_URI   = os.getenv('OAUTH_REDIRECT_URI', 'https://backend-mail-1.onrender.com/api/gmail/callback')
FRONTEND_URL         = os.getenv('FRONTEND_URL', 'https://bs-mailnotif-nine.vercel.app')
GMAIL_SCOPES         = ['https://www.googleapis.com/auth/gmail.readonly']

_init_firebase()
notifier_status = {"running": False}

# Middleware JWT pour sécuriser les endpoints
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Vérifier le token dans le header Authorization
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token JWT requis'}), 401
        
        try:
            # Décoder le token
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_id = payload['user_id']
            user_email = payload['email']
            
            # Vérifier que l'utilisateur existe
            db = get_db()
            with db.cursor() as cur:
                cur.execute("SELECT id, email FROM users WHERE id = %s AND email = %s", (user_id, user_email))
                user = cur.fetchone()
                
            if not user:
                return jsonify({'error': 'Utilisateur non trouvé'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expiré'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalide'}), 401
        except Exception as e:
            print(f"[JWT ERROR] {e}")
            return jsonify({'error': 'Erreur de validation du token'}), 401
        finally:
            if 'db' in locals():
                db.close()
        
        # Ajouter les infos utilisateur à la request
        request.current_user = {'id': user_id, 'email': user_email}
        
        return f(*args, **kwargs)
    
    return decorated

def generate_token(user_id: int, email: str) -> str:
    """Génère un token JWT pour l'utilisateur."""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=24),  # Expire dans 24h
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


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
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_mode       VARCHAR(10) DEFAULT 'light'")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_secondary  VARCHAR(20)")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_updated_at TIMESTAMP DEFAULT NOW()")
            # OAuth 2.0 Gmail tokens
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_access_token   TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_refresh_token  TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_token_expiry   BIGINT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_connected_email VARCHAR(150)")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token TEXT")
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


# ─── GOOGLE OAUTH 2.0 ────────────────────────────────────────────────────────

def _build_oauth_client_config():
    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [OAUTH_REDIRECT_URI],
        }
    }


def _get_gmail_service(user_email: str):
    """
    Build an authenticated Gmail API service for user_email.
    Automatically refreshes the access token if expired.
    Returns None if the user has no OAuth tokens.
    """
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT gmail_access_token, gmail_refresh_token, gmail_token_expiry "
                "FROM users WHERE email = %s AND is_verified = 1",
                (user_email,)
            )
            row = cur.fetchone()
    finally:
        _return_db(db)

    if not row or not row.get('gmail_refresh_token'):
        return None

    expiry_dt = (
        datetime.utcfromtimestamp(row['gmail_token_expiry'])
        if row.get('gmail_token_expiry') else None
    )

    creds = Credentials(
        token=row.get('gmail_access_token'),
        refresh_token=row['gmail_refresh_token'],
        token_uri='https://oauth2.googleapis.com/token',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=GMAIL_SCOPES,
        expiry=expiry_dt,
    )

    if not creds.valid:
        try:
            creds.refresh(GoogleRequest())
            db2 = get_db()
            try:
                with db2.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET gmail_access_token=%s, gmail_token_expiry=%s WHERE email=%s",
                        (
                            creds.token,
                            int(creds.expiry.timestamp()) if creds.expiry else None,
                            user_email,
                        ),
                    )
                db2.commit()
            finally:
                _return_db(db2)
        except Exception as e:
            print(f"[OAuth] Token refresh failed for {user_email}: {e}")
            return None

    return build('gmail', 'v1', credentials=creds)


@app.route('/api/gmail/connect')
def gmail_oauth_connect():
    """Initie le flow OAuth 2.0 Google — redirige l'utilisateur vers Google."""
    user_email = request.args.get('email', '').strip().lower()
    if not _is_valid_email(user_email):
        return jsonify({'error': 'email requis'}), 400
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'error': 'OAuth non configuré côté serveur (variables manquantes)'}), 500

    # Encode l'email dans le state (signé JWT — protège contre le CSRF)
    state = jwt.encode(
        {'email': user_email, 'iat': int(time.time()), 'exp': int(time.time()) + 600},
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    flow = Flow.from_client_config(
        _build_oauth_client_config(),
        scopes=GMAIL_SCOPES,
        redirect_uri=OAUTH_REDIRECT_URI,
    )
    auth_url, _ = flow.authorization_url(
        access_type='offline',
        prompt='consent',        # force refresh_token à chaque fois
        include_granted_scopes='true',
        state=state,
    )
    return redirect(auth_url)


@app.route('/api/gmail/callback')
def gmail_oauth_callback():
    """Callback Google OAuth — échange le code, sauvegarde les tokens, redirige vers le frontend."""
    error = request.args.get('error')
    if error:
        return redirect(f"{FRONTEND_URL}?gmail_error={error}")

    code  = request.args.get('code')
    state = request.args.get('state')

    if not code or not state:
        return redirect(f"{FRONTEND_URL}?gmail_error=missing_params")

    # Vérifier et décoder le state JWT
    try:
        payload    = jwt.decode(state, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_email = payload.get('email', '')
        if not _is_valid_email(user_email):
            raise ValueError('invalid email in state')
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError) as e:
        print(f"[OAuth] State invalid: {e}")
        return redirect(f"{FRONTEND_URL}?gmail_error=state_invalid")

    try:
        # Échanger le code contre des tokens (sans vérif CSRF — le JWT fait office de preuve)
        flow = Flow.from_client_config(
            _build_oauth_client_config(),
            scopes=GMAIL_SCOPES,
            redirect_uri=OAUTH_REDIRECT_URI,
        )
        flow.fetch_token(code=code)
        creds = flow.credentials

        # Récupérer l'adresse Gmail autorisée
        gmail_svc    = build('gmail', 'v1', credentials=creds)
        profile      = gmail_svc.users().getProfile(userId='me').execute()
        gmail_email  = profile.get('emailAddress', '')

        # Sauvegarder les tokens en base
        db = get_db()
        try:
            with db.cursor() as cur:
                cur.execute(
                    """UPDATE users SET
                        gmail_access_token    = %s,
                        gmail_refresh_token   = %s,
                        gmail_token_expiry    = %s,
                        gmail_connected_email = %s,
                        gmail_address = COALESCE(NULLIF(gmail_address,''), %s)
                    WHERE email = %s AND is_verified = 1""",
                    (
                        creds.token,
                        creds.refresh_token,
                        int(creds.expiry.timestamp()) if creds.expiry else None,
                        gmail_email,
                        gmail_email,
                        user_email,
                    ),
                )
            db.commit()
        finally:
            _return_db(db)

        print(f"[OAuth] Gmail connecté pour {user_email} → {gmail_email}")
        return redirect(f"{FRONTEND_URL}?gmail_connected=1&gmail_email={gmail_email}")

    except Exception as e:
        print(f"[OAuth] Callback error: {e}")
        return redirect(f"{FRONTEND_URL}?gmail_error=callback_failed")


@app.route('/api/gmail/disconnect', methods=['POST'])
def gmail_disconnect():
    """Révoque et supprime les tokens OAuth de l'utilisateur."""
    data       = request.get_json() or {}
    user_email = _str(data.get('email'), 150).lower()
    if not _is_valid_email(user_email):
        return jsonify({'error': 'email requis'}), 400

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                """UPDATE users SET
                    gmail_access_token = NULL, gmail_refresh_token = NULL,
                    gmail_token_expiry = NULL, gmail_connected_email = NULL
                WHERE email = %s""",
                (user_email,),
            )
        db.commit()
    finally:
        _return_db(db)

    return jsonify({'success': True})


@app.route('/api/gmail/status')
def gmail_oauth_status():
    """Retourne le statut de connexion OAuth Gmail de l'utilisateur."""
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'connected': False}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT gmail_refresh_token, gmail_connected_email, gmail_token_expiry "
                "FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
        if not row or not row.get('gmail_refresh_token'):
            return jsonify({'connected': False, 'gmail_email': None, 'expired': False})

        expiry  = row.get('gmail_token_expiry')
        expired = bool(expiry and int(time.time()) > expiry)
        return jsonify({
            'connected':   True,
            'gmail_email': row.get('gmail_connected_email'),
            'expired':     expired,
        })
    finally:
        _return_db(db)


# Rétrocompatibilité — utilisé par l'ancienne version frontend
@app.route('/api/auth/gmail-status')
def gmail_status_legacy():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'connected': False}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT gmail_refresh_token FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
        return jsonify({'connected': bool(row and row.get('gmail_refresh_token'))})
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


@app.route('/api/emails')
def get_emails():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({"emails": [], "page": 1, "limit": 20, "total": 0, "pages": 1})

    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(50, max(1, int(request.args.get('limit', 20))))
    except (ValueError, TypeError):
        page, limit = 1, 20

    EMPTY = {"emails": [], "page": page, "limit": limit, "total": 0, "pages": 1}

    try:
        service = _get_gmail_service(email)
        if not service:
            return jsonify(EMPTY)

        # Paramètre de pagination Gmail (pageToken pour pages > 1)
        kwargs: dict = {'userId': 'me', 'maxResults': limit, 'labelIds': ['INBOX']}
        if page > 1:
            # Récupérer le pageToken correspondant à la page demandée
            token = None
            for _ in range(page - 1):
                r = service.users().messages().list(**kwargs, **(
                    {'pageToken': token} if token else {}
                )).execute()
                token = r.get('nextPageToken')
                if not token:
                    return jsonify(EMPTY)
            kwargs['pageToken'] = token

        result   = service.users().messages().list(**kwargs).execute()
        msg_refs = result.get('messages', [])
        total    = result.get('resultSizeEstimate', len(msg_refs))

        emails = []
        for ref in msg_refs:
            try:
                msg = service.users().messages().get(
                    userId='me', id=ref['id'],
                    format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date'],
                ).execute()
                hdrs = {h['name']: h['value'] for h in msg.get('payload', {}).get('headers', [])}
                emails.append({
                    "id":      msg['id'],
                    "subject": hdrs.get('Subject', '(Sans objet)'),
                    "sender":  hdrs.get('From', 'Inconnu'),
                    "date":    hdrs.get('Date', ''),
                    "snippet": msg.get('snippet', '')[:150],
                    "unread":  'UNREAD' in msg.get('labelIds', []),
                })
            except HttpError:
                continue

        return jsonify({
            "emails": emails, "page": page, "limit": limit,
            "total": total, "pages": max(1, (total + limit - 1) // limit),
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
        service = _get_gmail_service(email)
        if not service:
            return jsonify({"total_messages": 0, "unread_count": 0, "email": email})

        profile = service.users().getProfile(userId='me').execute()
        total   = profile.get('messagesTotal', 0)

        unread_res = service.users().messages().list(
            userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=1
        ).execute()
        unread = unread_res.get('resultSizeEstimate', 0)

        return jsonify({"total_messages": total, "unread_count": unread, "email": email})
    except Exception as e:
        print(f"[ERROR] get_stats: {e}")
        return jsonify({"total_messages": 0, "unread_count": 0, "email": email})


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
                "green_api_token, app_password, avatar, theme_color, font_family, theme_mode, theme_secondary, "
                "to_char(theme_updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS theme_updated_at "
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
                "theme_color": "", "font_family": "", "theme_mode": "light",
                "theme_secondary": "", "theme_updated_at": None
            })
        user = dict(user)
        for key in ["phone", "gmail_address", "telegram_chat_id", "green_api_instance",
                    "green_api_token", "avatar", "theme_color", "font_family",
                    "theme_mode", "theme_secondary"]:  # theme_updated_at is a timestamp, handled separately
            if user.get(key) is None:
                user[key] = ""
        user['app_password_set'] = bool(user.pop('app_password', None))
        if not user.get('theme_mode'):
            user['theme_mode'] = 'light'
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
            theme_color     = _str(data.get('theme_color'),     20) or None
            font_family     = _str(data.get('font_family'),     60) or None
            theme_mode      = _str(data.get('theme_mode'),      10) or None
            theme_secondary = _str(data.get('theme_secondary'), 20) or None
            if theme_mode and theme_mode not in ('light', 'dark'):
                theme_mode = None
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
                        theme_color      = COALESCE(%s, theme_color),
                        font_family      = COALESCE(%s, font_family),
                        theme_mode       = COALESCE(%s, theme_mode),
                        theme_secondary  = COALESCE(%s, theme_secondary),
                        theme_updated_at = CASE WHEN %s THEN NOW() ELSE theme_updated_at END
                    WHERE email = %s AND is_verified = 1""",
                    (name, data.get('phone'), data.get('gmail_address'),
                     data.get('telegram_chat_id'), data.get('green_api_instance'),
                     data.get('green_api_token'), app_password,
                     avatar, theme_color, font_family, theme_mode, theme_secondary,
                     bool(theme_color or font_family or theme_mode or theme_secondary),
                     email)
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
                        avatar           = COALESCE(%s, avatar),
                        theme_color      = COALESCE(%s, theme_color),
                        font_family      = COALESCE(%s, font_family),
                        theme_mode       = COALESCE(%s, theme_mode),
                        theme_secondary  = COALESCE(%s, theme_secondary),
                        theme_updated_at = CASE WHEN %s THEN NOW() ELSE theme_updated_at END
                    WHERE email = %s AND is_verified = 1""",
                    (name, data.get('phone'), data.get('gmail_address'),
                     data.get('telegram_chat_id'), data.get('green_api_instance'),
                     data.get('green_api_token'),
                     avatar, theme_color, font_family, theme_mode, theme_secondary,
                     bool(theme_color or font_family or theme_mode or theme_secondary),
                     email)
                )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] update_user_settings: {e}")
        return jsonify({"error": "Erreur lors de la mise à jour"}), 500
    finally:
        _return_db(db)


# ─── EMAIL MONITOR ────────────────────────────────────────────────────────────

def _send_fcm_notification(fcm_token: str, title: str, body: str):
    if not _firebase_initialized or not fcm_token:
        return
    try:
        message = fb_messaging.Message(
            notification=fb_messaging.Notification(title=title, body=body),
            data={'click_action': 'FLUTTER_NOTIFICATION_CLICK'},
            token=fcm_token,
        )
        fb_messaging.send(message)
        print(f"[FCM] Push envoyée → {fcm_token[:20]}...")
    except Exception as e:
        print(f"[FCM] Erreur push: {e}")


def _send_whatsapp_notification(user, sender: str, subject: str, snippet: str):
    instance = user.get('green_api_instance')
    token    = user.get('green_api_token')
    phone    = user.get('phone')
    if not instance or not token or not phone:
        return
    match = re.match(r'^(.+?)\s*<', sender)
    sender_name = match.group(1).strip().strip('"') if match else sender.split('@')[0]
    text = (
        f"📧 *MailNotifier — Nouveau mail !*\n\n"
        f"*De :* {sender_name}\n"
        f"*Objet :* {subject}\n"
        f"*Aperçu :* {snippet[:150]}"
    )
    try:
        url = f"https://api.green-api.com/waInstance{instance}/sendMessage/{token}"
        resp = requests.post(url, json={"chatId": f"{phone}@c.us", "message": text}, timeout=10)
        if resp.ok:
            print(f"[Monitor] WhatsApp OK → {phone}")
        else:
            print(f"[Monitor] WhatsApp erreur: {resp.status_code}")
    except Exception as e:
        print(f"[Monitor] WhatsApp exception: {e}")


_SPAM_KEYWORDS = ['unsubscribe', 'désabonner', 'newsletter', 'promo', 'noreply', 'no-reply',
                  'publicite', 'publicité', 'offre', 'soldes', 'réduction', 'discount']
_IMPORTANT_KEYWORDS = ['urgent', 'important', 'facture', 'invoice', 'paiement', 'payment',
                       'alerte', 'alert', 'sécurité', 'security', 'votre compte', 'your account']

def _classify_email(sender: str, subject: str, snippet: str) -> str:
    text = f"{sender} {subject} {snippet}".lower()
    if any(k in text for k in _IMPORTANT_KEYWORDS):
        return 'important'
    if any(k in text for k in _SPAM_KEYWORDS):
        return 'newsletter'
    return 'normal'


@app.route('/api/fcm/register', methods=['POST'])
def register_fcm_token():
    data  = request.get_json() or {}
    email = _str(data.get('email'), 150).lower()
    token = _str(data.get('fcm_token'), 500)
    if not _is_valid_email(email) or not token:
        return jsonify({'error': 'email et fcm_token requis'}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET fcm_token=%s WHERE email=%s AND is_verified=1", (token, email))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        _return_db(db)


def _send_telegram_notification(chat_id, sender, subject, snippet, user_email):
    if not TELEGRAM_BOT_TOKEN:
        print("[Monitor] TELEGRAM_BOT_TOKEN manquant — notification ignoree")
        return
    match = re.match(r'^(.+?)\s*<', sender)
    sender_name = match.group(1).strip().strip('"') if match else sender.split('@')[0]
    text = (
        f"📬 *MailNotifier*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Vous avez reçu un nouveau mail !\n\n"
        f"👤 *De :* {sender_name}\n"
        f"📌 *Objet :* {subject}\n"
        f"💬 *Aperçu :*\n_{snippet[:200]}_\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔔 Consultez votre boîte mail pour plus de détails."
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


def _check_user_emails_gmail(user):
    """Vérifie les nouveaux mails d'un utilisateur via Gmail API (OAuth 2.0)."""
    user_email      = user['email']
    chat_id         = user.get('telegram_chat_id')
    user_id         = user['id']
    last_history_id = user.get('last_history_id')

    try:
        service = _get_gmail_service(user_email)
        if not service:
            return

        profile            = service.users().getProfile(userId='me').execute()
        current_history_id = str(profile.get('historyId', ''))

        if not last_history_id:
            # Premier passage : mémoriser le historyId sans notifier
            _save_last_uid(user_id, current_history_id)
            print(f"[Monitor] Init historyId={current_history_id} pour {user_email}")
            return

        try:
            history = service.users().history().list(
                userId='me',
                startHistoryId=last_history_id,
                historyTypes=['messageAdded'],
            ).execute()

            new_ids = []
            for record in history.get('history', []):
                for added in record.get('messagesAdded', []):
                    msg = added.get('message', {})
                    if 'INBOX' in msg.get('labelIds', []):
                        new_ids.append(msg['id'])

            for msg_id in new_ids:
                try:
                    msg = service.users().messages().get(
                        userId='me', id=msg_id,
                        format='metadata',
                        metadataHeaders=['Subject', 'From'],
                    ).execute()
                    hdrs     = {h['name']: h['value'] for h in msg.get('payload', {}).get('headers', [])}
                    subject  = hdrs.get('Subject', '(Sans objet)')
                    sender   = hdrs.get('From', 'Inconnu')
                    snippet  = msg.get('snippet', '')[:200]
                    category = _classify_email(sender, subject, snippet)
                    print(f"[Monitor] Email [{category}] : {subject[:60]}")

                    if chat_id and category != 'newsletter':
                        _send_telegram_notification(chat_id, sender, subject, snippet, user_email)

                    if category == 'important':
                        _send_whatsapp_notification(user, sender, subject, snippet)

                    match_s = re.match(r'^(.+?)\s*<', sender)
                    sender_name = match_s.group(1).strip().strip('"') if match_s else sender.split('@')[0]
                    fcm_token = user.get('fcm_token')
                    if fcm_token:
                        emoji = '🔴' if category == 'important' else ('📰' if category == 'newsletter' else '✉️')
                        _send_fcm_notification(
                            fcm_token,
                            title="MailNotifier — Nouveau mail",
                            body=f"{emoji} {sender_name} : {subject[:80]}",
                        )
                except HttpError as e:
                    print(f"[Monitor] Erreur lecture msg {msg_id}: {e}")

        except HttpError as e:
            if 'Invalid startHistoryId' in str(e):
                # historyId expiré (> 7 jours) — réinitialiser
                print(f"[Monitor] historyId expiré pour {user_email}, réinitialisation")
                _save_last_uid(user_id, current_history_id)
                return
            raise

        _save_last_uid(user_id, current_history_id)

    except Exception as e:
        print(f"[Monitor] Erreur Gmail API pour {user_email}: {e}")


def _check_all_users():
    """Récupère tous les utilisateurs surveillables et vérifie leurs mails via Gmail API."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, email, telegram_chat_id, last_history_id,
                       fcm_token, phone, green_api_instance, green_api_token
                FROM users
                WHERE gmail_refresh_token IS NOT NULL
                  AND (
                    (telegram_chat_id IS NOT NULL AND telegram_chat_id != '')
                    OR fcm_token IS NOT NULL
                    OR green_api_instance IS NOT NULL
                  )
                  AND is_verified = 1
            """)
            users = [dict(u) for u in cur.fetchall()]
    finally:
        _return_db(db)

    if not users:
        return

    print(f"[Monitor] Vérification Gmail API de {len(users)} utilisateur(s)...")
    for user in users:
        try:
            _check_user_emails_gmail(user)
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
    """Endpoint de debug : liste les utilisateurs et leur etat OAuth Gmail."""
    logs = []

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, email, gmail_address, gmail_connected_email, telegram_chat_id, last_history_id,
                       (gmail_refresh_token IS NOT NULL) as has_password
                FROM users WHERE is_verified = 1
            """)
            all_users = [dict(u) for u in cur.fetchall()]
    finally:
        _return_db(db)

    logs.append(f"Total utilisateurs: {len(all_users)}")
    for u in all_users:
        logs.append(
            f"  - {u['email']} | gmail={u['gmail_address']} | "
            f"oauth={'OUI' if u['has_password'] else 'NON'} | "
            f"telegram={u['telegram_chat_id']} | last_uid={u['last_history_id']}"
        )

    eligible = [u for u in all_users if u['has_password'] and u['telegram_chat_id']]
    logs.append(f"Eligibles Gmail API OAuth (refresh_token + telegram): {len(eligible)}")

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
@limiter.limit("20 per minute")
@app.route('/api/preferences', methods=['GET'])
@limiter.limit("20 per minute")
@token_required
def get_preferences():
    """Récupérer les préférences utilisateur (sécurisé avec JWT)."""
    user_id = request.current_user['id']
    
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT preference_key, preference_value, updated_at, version
                FROM user_preferences 
                WHERE user_id = %s
                ORDER BY updated_at DESC
            """, (user_id,))
            
            preferences = cur.fetchall()
            
        return jsonify({
            'preferences': [
                {
                    'key': row['preference_key'],
                    'value': row['preference_value'],
                    'updated_at': str(row['updated_at']),
                    'version': row['version']
                } for row in preferences
            ],
            'user_id': user_id
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Get preferences: {e}")
        return jsonify({'error': 'Erreur lors de la récupération des préférences'}), 500
        
    finally:
        if 'db' in locals():
            db.close()

@app.route('/api/preferences', methods=['POST'])
@limiter.limit("20 per minute")
@token_required
def update_preferences():
    """Mettre à jour les préférences utilisateur (sécurisé avec JWT + gestion conflits)."""
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Données invalides'}), 400
    
    preferences = data.get('preferences', {})
    client_version = data.get('version', 0)
    
    if not preferences:
        return jsonify({'error': 'preferences requis'}), 400
    
    user_id = request.current_user['id']
    
    try:
        db = get_db()
        with db.cursor() as cur:
            # Vérifier la version actuelle pour gestion des conflits
            cur.execute("""
                SELECT MAX(version) as current_version
                FROM user_preferences 
                WHERE user_id = %s
            """, (user_id,))
            
            result = cur.fetchone()
            current_version = result['current_version'] or 0
            
            # Gestion des conflits : si la version client est plus ancienne, retourner conflit
            if client_version > 0 and client_version < current_version:
                # Récupérer les préférences actuelles
                cur.execute("""
                    SELECT preference_key, preference_value, version
                    FROM user_preferences 
                    WHERE user_id = %s AND version = %s
                """, (user_id, current_version))
                
                current_prefs = cur.fetchall()
                
                return jsonify({
                    'error': 'CONFLICT',
                    'message': 'Vos préférences ont été modifiées sur un autre appareil',
                    'current_preferences': {
                        pref['preference_key']: pref['preference_value'] 
                        for pref in current_prefs
                    },
                    'current_version': current_version
                }), 409
            
            # Nouvelle version pour cette mise à jour
            new_version = current_version + 1
            
            # Insérer les nouvelles préférences avec version
            for key, value in preferences.items():
                cur.execute("""
                    INSERT INTO user_preferences (user_id, preference_key, preference_value, version)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id, preference_key) 
                    DO UPDATE SET 
                        preference_value = EXCLUDED.preference_value,
                        version = EXCLUDED.version,
                        updated_at = CURRENT_TIMESTAMP
                """, (user_id, key, value, new_version))
            
            db.commit()
            
        # Notifier WebSocket pour temps réel
        socketio.emit('preference_updated', {
            'user_id': user_id,
            'preferences': preferences,
            'version': new_version,
            'updated_at': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")
        
        print(f"[PREFERENCES] Préférences mises à jour pour user {user_id} (version {new_version})")
        
        return jsonify({
            'message': 'Préférences mises à jour avec succès',
            'version': new_version
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Update preferences: {e}")
        return jsonify({'error': 'Erreur lors de la mise à jour des préférences'}), 500
        
    finally:
        if 'db' in locals():
            db.close()

@app.route('/api/auth/token', methods=['POST'])
@limiter.limit("10 per minute")
def get_auth_token():
    """Génère un token JWT pour l'utilisateur authentifié."""
    email = request.json.get('email')
    password = request.json.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email et mot de passe requis'}), 400
    
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
            
            # Générer le token JWT
            token = generate_token(user['id'], user['email'])
            
            return jsonify({
                'token': token,
                'user_id': user['id'],
                'email': user['email'],
                'expires_in': 24 * 3600  # 24 heures en secondes
            }), 200
            
    except Exception as e:
        print(f"[ERROR] Auth token: {e}")
        return jsonify({'error': 'Erreur lors de l\'authentification'}), 500
        
    finally:
        if 'db' in locals():
            db.close()

@socketio.on('connect')
def handle_connect():
    """Gère la connexion WebSocket avec authentification JWT."""
    token = request.args.get('token')
    user_id = None
    
    if token:
        try:
            # Valider le token JWT
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_id = payload['user_id']
            
            # Vérifier que l'utilisateur existe
            db = get_db()
            with db.cursor() as cur:
                cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()
                
            if user:
                join_room(f"user_{user_id}")
                print(f"[WEBSOCKET] User {user_id} connecté avec succès")
                emit('connected', {
                    'message': f'Connecté avec succès pour user {user_id}',
                    'user_id': user_id,
                    'timestamp': datetime.utcnow().isoformat()
                })
            else:
                print(f"[WEBSOCKET] Token valide mais utilisateur {user_id} non trouvé")
                emit('error', {'message': 'Utilisateur non trouvé'})
                return False
                
        except jwt.ExpiredSignatureError:
            print(f"[WEBSOCKET] Token expiré")
            emit('error', {'message': 'Token expiré'})
            return False
        except jwt.InvalidTokenError:
            print(f"[WEBSOCKET] Token invalide")
            emit('error', {'message': 'Token invalide'})
            return False
        except Exception as e:
            print(f"[WEBSOCKET] Erreur validation token: {e}")
            emit('error', {'message': 'Erreur d\'authentification'})
            return False
        finally:
            if 'db' in locals():
                db.close()
    else:
        print(f"[WEBSOCKET] Connexion sans token")
        emit('error', {'message': 'Token requis'})
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Gère la déconnexion WebSocket."""
    print(f"[WEBSOCKET] Utilisateur déconnecté")

@socketio.on('ping')
def handle_ping():
    """Gère le ping pour keep-alive."""
    emit('pong', {'timestamp': datetime.utcnow().isoformat()})

@socketio.on('join_user_room')
def handle_join_user_room(data):
    """Rejoint la room utilisateur spécifique avec validation."""
    user_id = data.get('user_id')
    token = data.get('token')
    
    if not token:
        emit('error', {'message': 'Token requis'})
        return
    
    try:
        # Valider le token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        token_user_id = payload['user_id']
        
        if str(token_user_id) != str(user_id):
            emit('error', {'message': 'Token invalide pour cet utilisateur'})
            return
        
        join_room(f"user_{user_id}")
        emit('joined_room', {
            'room': f"user_{user_id}",
            'timestamp': datetime.utcnow().isoformat()
        })
        
        print(f"[WEBSOCKET] User {user_id} a rejoint sa room")
        
    except jwt.InvalidTokenError:
        emit('error', {'message': 'Token invalide'})
    except Exception as e:
        print(f"[WEBSOCKET] Erreur join room: {e}")
        emit('error', {'message': 'Erreur lors de la jonction de la room'})

# Système de ping/pong automatique pour maintenir les connexions
@socketio.on('keep_alive')
def handle_keep_alive():
    """Répond au keep-alive pour maintenir la connexion."""
    emit('keep_alive_response', {
        'timestamp': datetime.utcnow().isoformat(),
        'status': 'alive'
    })

@app.route('/api/dashboard/advanced-stats', methods=['GET'])
@limiter.limit("20 per minute")
def get_advanced_stats():
    """Endpoint pour récupérer les statistiques avancées du tableau de bord."""
    email = request.args.get('email')
    period = int(request.args.get('period', 30))  # jours
    status = request.args.get('status', 'all')
    sender_filter = request.args.get('sender', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if not email:
        return jsonify({'error': 'Email requis'}), 400
    
    try:
        db = get_db()
        with db.cursor() as cur:
            # Statistiques générales
            cur.execute("""
                SELECT 
                    COUNT(*) as total_emails,
                    SUM(CASE WHEN is_read = false THEN 1 ELSE 0 END) as unread_emails,
                    SUM(CASE WHEN is_sent = true THEN 1 ELSE 0 END) as sent_emails,
                    DATE(sent_at) as last_email_date
                FROM emails 
                WHERE user_email = %s
            """, (email,))
            
            stats = cur.fetchone()
            
            # Évolution temporelle
            cur.execute("""
                SELECT 
                    DATE(sent_at) as date,
                    COUNT(*) as count,
                    SUM(CASE WHEN is_read = false THEN 1 ELSE 0 END) as unread
                FROM emails 
                WHERE user_email = %s 
                    AND sent_at >= CURRENT_DATE - INTERVAL '%s days'
                GROUP BY DATE(sent_at)
                ORDER BY date DESC
            """, (email, period))
            
            evolution = cur.fetchall()
            
            # Répartition par statut
            cur.execute("""
                SELECT 
                    CASE WHEN is_read = true THEN 'Lus' ELSE 'Non lus' END as status,
                    COUNT(*) as count
                FROM emails 
                WHERE user_email = %s
                GROUP BY is_read
            """, (email,))
            
            status_distribution = cur.fetchall()
            
            # Top expéditeurs
            cur.execute("""
                SELECT 
                    sender,
                    COUNT(*) as count
                FROM emails 
                WHERE user_email = %s
                    AND sender IS NOT NULL
                GROUP BY sender
                ORDER BY count DESC
                LIMIT 10
            """, (email,))
            
            top_senders = cur.fetchall()
            
        return jsonify({
            'total_emails': int(stats['total_emails'] or 0),
            'unread_emails': int(stats['unread_emails'] or 0),
            'sent_emails': int(stats['sent_emails'] or 0),
            'average_per_day': round(int(stats['total_emails'] or 0) / period, 1),
            'evolution': [
                {
                    'date': str(row['date']),
                    'count': int(row['count']),
                    'unread': int(row['unread'])
                } for row in evolution
            ],
            'status_distribution': [
                {
                    'status': row['status'],
                    'count': int(row['count'])
                } for row in status_distribution
            ],
            'top_senders': [
                {
                    'sender': row['sender'],
                    'count': int(row['count'])
                } for row in top_senders
            ]
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Advanced stats: {e}")
        return jsonify({'error': 'Erreur lors de la récupération des statistiques'}), 500
        
    finally:
        if 'db' in locals():
            db.close()


def init_user_preferences():
    """Initialise la table user_preferences pour la synchronisation."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    preference_key VARCHAR(100) NOT NULL,
                    preference_value TEXT,
                    version INTEGER DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, preference_key)
                )
            """)
            
            # Ajouter le champ version s'il n'existe pas
            cur.execute("""
                ALTER TABLE user_preferences 
                ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1
            """)
            
            db.commit()
            print("[DB] Table user_preferences créée/mise à jour avec succès")
    except Exception as e:
        print(f"[ERROR] Erreur création table user_preferences: {e}")
        db.rollback()
    finally:
        db.close()

def _startup():
    # Skip startup in test environment (avoids real DB connections and daemon threads)
    if os.getenv('TESTING'):
        return
    print("[STARTUP] Debut de l'initialisation...")
    try:
        init_db()
        init_user_preferences()  # Initialiser la table des préférences
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
