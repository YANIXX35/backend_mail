print("=== MailNotifier API v4.3 - GMAIL OAUTH + FCM ===")
import os
import re
import time
import random
import smtplib
import requests
import hashlib
import threading
import json as _json  # noqa: F401 – used by inner function scopes via re-import
from ssl import create_default_context
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.errors import HttpError
from flask import Flask, jsonify, request, redirect, render_template  # noqa: F401
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room  # noqa: F401
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
import psycopg2.pool
import bcrypt
import jwt
import base64

# ── CACHE MÉMOIRE (TTL simple, thread-safe) ────────────────────────────────────
_cache: dict = {}
_cache_lock  = threading.Lock()

def _cache_get(key: str):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.time() < entry['exp']:
            return entry['val']
        return None

def _cache_set(key: str, val, ttl: int):
    with _cache_lock:
        _cache[key] = {'val': val, 'exp': time.time() + ttl}

def _cache_del(key: str):
    with _cache_lock:
        _cache.pop(key, None)
from functools import wraps
import firebase_admin
from firebase_admin import credentials as fb_credentials, messaging as fb_messaging
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import cloudinary
import cloudinary.uploader

load_dotenv()

# ─── SENTRY ───────────────────────────────────────────────────────────────────
_sentry_dsn = os.getenv('SENTRY_DSN')
if _sentry_dsn:
    sentry_sdk.init(
        dsn=_sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.2,   # 20 % des requêtes tracées (performance)
        profiles_sample_rate=0.1,
        environment=os.getenv('ENVIRONMENT', 'production'),
        send_default_pii=False,   # ne jamais envoyer d'infos perso
        before_send=lambda event, hint: _sentry_scrub(event),
    )
    print(f"[Sentry] Initialisé — env={os.getenv('ENVIRONMENT','production')}")
else:
    print("[Sentry] SENTRY_DSN non défini — monitoring désactivé")

def _sentry_scrub(event: dict) -> dict:
    """Supprime les tokens, mots de passe et emails des événements Sentry."""
    for frame in (event.get('exception') or {}).get('values', []):
        for f in (frame.get('stacktrace') or {}).get('frames', []):
            for key in list((f.get('vars') or {}).keys()):
                if any(s in key.lower() for s in ('password', 'token', 'secret', 'key', 'email')):
                    f['vars'][key] = '[REDACTED]'
    return event

# ─── CLOUDINARY INIT ──────────────────────────────────────────────────────────
_cloudinary_enabled = bool(os.getenv('CLOUDINARY_CLOUD_NAME'))
if _cloudinary_enabled:
    cloudinary.config(
        cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
        api_key    = os.getenv('CLOUDINARY_API_KEY'),
        api_secret = os.getenv('CLOUDINARY_API_SECRET'),
        secure     = True,
    )
    print("[Cloudinary] Initialisé")
else:
    print("[Cloudinary] Variables manquantes — stockage base64 utilisé en fallback")

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

# ─── GREEN-API (WhatsApp) — instance partagée admin ───────────────────────────
GREEN_API_URL      = (os.getenv('GREEN_API_URL') or 'https://api.green-api.com').strip()
GREEN_API_INSTANCE = (os.getenv('GREEN_API_INSTANCE') or '').strip() or None
GREEN_API_TOKEN    = (os.getenv('GREEN_API_TOKEN') or '').strip() or None

# ─── GOOGLE OAUTH CONFIG ──────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
OAUTH_REDIRECT_URI   = os.getenv('OAUTH_REDIRECT_URI', 'https://backend-mail-1.onrender.com/api/gmail/callback')
FRONTEND_URL         = os.getenv('FRONTEND_URL', 'https://bs-mailnotif-nine.vercel.app')
GMAIL_SCOPES         = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
]

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
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp_chat_id VARCHAR(80)")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_enabled BOOLEAN DEFAULT TRUE")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp_enabled BOOLEAN DEFAULT TRUE")
            # Pré-remplir le chatId @lid connu pour kyliyanisse (checkWhatsapp retourne 404 sur ce serveur)
            cur.execute("""
                UPDATE users SET whatsapp_chat_id='62508954075303@lid'
                WHERE email='kyliyanisse@gmail.com' AND (whatsapp_chat_id IS NULL OR whatsapp_chat_id='')
            """)
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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS whatsapp_email_map (
                    wa_msg_id VARCHAR(100) PRIMARY KEY,
                    user_email VARCHAR(150) NOT NULL,
                    gmail_message_id VARCHAR(100) NOT NULL,
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
        msg['From'] = f'MailNotifier <{SMTP_EMAIL}>'
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

            cur.execute("SELECT id FROM users WHERE email = %s AND is_verified = 1", (email,))
            new_user = cur.fetchone()
            token = generate_token(new_user['id'], email) if new_user else None

            return jsonify({'message': 'Compte cree avec succes !', 'name': otp['name'], 'token': token}), 201
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

        token = generate_token(user['id'], email)
        return jsonify({
            'message': 'Connexion reussie',
            'name':    user['name'],
            'email':   email,
            'role':    user.get('role', 'user'),
            'token':   token,
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
@token_required
def gmail_oauth_status():
    """Retourne le statut de connexion OAuth Gmail + si le scope send est disponible."""
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'connected': False}), 400

    cache_key = f"gmail_status:{email}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT gmail_access_token, gmail_refresh_token, gmail_connected_email, gmail_token_expiry "
                "FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
        if not row or not row.get('gmail_refresh_token'):
            result = {'connected': False, 'gmail_email': None, 'expired': False, 'can_send': False}
        else:
            expiry  = row.get('gmail_token_expiry')
            expired = bool(expiry and int(time.time()) > expiry)

            # Vérifier si le token a le scope gmail.send (via tokeninfo Google)
            can_send = False
            access_token = row.get('gmail_access_token')
            if access_token:
                try:
                    tr = requests.get(
                        'https://oauth2.googleapis.com/tokeninfo',
                        params={'access_token': access_token},
                        timeout=4,
                    )
                    if tr.ok:
                        can_send = 'gmail.send' in tr.json().get('scope', '')
                    elif tr.status_code == 400:
                        # Token expiré — on tente un refresh pour obtenir le scope réel
                        svc = _get_gmail_service(email)
                        if svc:
                            with db.cursor() as cur2:
                                cur2.execute("SELECT gmail_access_token FROM users WHERE email=%s", (email,))
                                refreshed = cur2.fetchone()
                            if refreshed and refreshed.get('gmail_access_token'):
                                tr2 = requests.get(
                                    'https://oauth2.googleapis.com/tokeninfo',
                                    params={'access_token': refreshed['gmail_access_token']},
                                    timeout=4,
                                )
                                if tr2.ok:
                                    can_send = 'gmail.send' in tr2.json().get('scope', '')
                except Exception:
                    can_send = True  # en cas d'erreur réseau, on ne bloque pas l'utilisateur

            result = {
                'connected':   True,
                'gmail_email': row.get('gmail_connected_email'),
                'expired':     expired,
                'can_send':    can_send,
            }
        _cache_set(cache_key, result, ttl=60)
        return jsonify(result)
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
        "running":              notifier_status["running"],
        "email":                os.getenv('GMAIL_ADDRESS'),
        "telegram":             bool(TELEGRAM_BOT_TOKEN),
        "whatsapp":             bool(GREEN_API_INSTANCE and GREEN_API_TOKEN),
        "green_api_instance":   bool(GREEN_API_INSTANCE),
        "green_api_token":      bool(GREEN_API_TOKEN),
        "green_api_url":        GREEN_API_URL,
    })


@app.route('/api/emails')
@token_required
def get_emails():
    email = request.current_user['email']
    if not email:
        return jsonify({"emails": [], "page": 1, "limit": 20, "total": 0, "pages": 1})

    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(50, max(1, int(request.args.get('limit', 20))))
    except (ValueError, TypeError):
        page, limit = 1, 20

    EMPTY = {"emails": [], "page": page, "limit": limit, "total": 0, "pages": 1}

    # Cache 60s par user + page
    cache_key = f"emails:{email}:p{page}:l{limit}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

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
                subject = hdrs.get('Subject', '(Sans objet)')
                sender  = hdrs.get('From', 'Inconnu')
                snippet = msg.get('snippet', '')[:150]
                emails.append({
                    "id":       msg['id'],
                    "subject":  subject,
                    "sender":   sender,
                    "date":     hdrs.get('Date', ''),
                    "snippet":  snippet,
                    "unread":   'UNREAD' in msg.get('labelIds', []),
                    "category": _classify_email(sender, subject, snippet),
                })
            except HttpError:
                continue

        result_data = {
            "emails": emails, "page": page, "limit": limit,
            "total": total, "pages": max(1, (total + limit - 1) // limit),
        }
        _cache_set(cache_key, result_data, ttl=60)
        return jsonify(result_data)
    except Exception as e:
        print(f"[ERROR] get_emails: {e}")
        return jsonify({"error": "Erreur lors de la récupération des emails"}), 500


@app.route('/api/email/<message_id>')
def get_email_detail(message_id):
    email = request.args.get('email', '').strip().lower()
    if not email or not message_id:
        return jsonify({"error": "email et message_id requis"}), 400
    try:
        service = _get_gmail_service(email)
        if not service:
            return jsonify({"error": "Gmail non connecté"}), 401

        msg = service.users().messages().get(
            userId='me', id=message_id, format='full'
        ).execute()

        hdrs = {h['name']: h['value'] for h in msg.get('payload', {}).get('headers', [])}

        def _extract_body(payload):
            mime = payload.get('mimeType', '')
            if mime in ('text/html', 'text/plain'):
                data = payload.get('body', {}).get('data', '')
                if data:
                    import base64
                    return mime, base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='replace')
            for part in payload.get('parts', []):
                mime_type, content = _extract_body(part)
                if content:
                    return mime_type, content
            return '', ''

        mime_type, body = _extract_body(msg.get('payload', {}))
        subject = hdrs.get('Subject', '(Sans objet)')
        sender  = hdrs.get('From', 'Inconnu')
        snippet = msg.get('snippet', '')

        return jsonify({
            "id":        message_id,
            "subject":   subject,
            "sender":    sender,
            "to":        hdrs.get('To', ''),
            "date":      hdrs.get('Date', ''),
            "snippet":   snippet,
            "body":      body,
            "body_type": mime_type,
            "unread":    'UNREAD' in msg.get('labelIds', []),
            "category":  _classify_email(sender, subject, snippet),
        })
    except Exception as e:
        print(f"[ERROR] get_email_detail: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/email/reply', methods=['POST'])
@token_required
def reply_email():
    """Répond à un email Gmail via l'API Gmail (send)."""
    data = request.get_json(silent=True) or {}
    user_email   = data.get('email', '').strip().lower()
    message_id   = data.get('message_id', '').strip()
    reply_text   = data.get('reply_text', '').strip()

    if not user_email or not message_id or not reply_text:
        return jsonify({'error': 'Paramètres manquants (email, message_id, reply_text)'}), 400

    service = _get_gmail_service(user_email)
    if not service:
        return jsonify({'error': 'Gmail non connecté. Reconnectez Gmail dans les paramètres.'}), 403

    try:
        orig = service.users().messages().get(
            userId='me', id=message_id, format='metadata',
            metadataHeaders=['Subject', 'From', 'Message-ID', 'References']
        ).execute()

        hdrs      = {h['name']: h['value'] for h in orig.get('payload', {}).get('headers', [])}
        thread_id = orig.get('threadId', '')
        subject   = hdrs.get('Subject', '')
        if not subject.lower().startswith('re:'):
            subject = f'Re: {subject}'
        to_addr      = hdrs.get('From', '')
        orig_msg_id  = hdrs.get('Message-ID', '')
        existing_refs = hdrs.get('References', '')
        references   = (f'{existing_refs} {orig_msg_id}').strip() if orig_msg_id else existing_refs

        msg = MIMEText(reply_text, 'plain', 'utf-8')
        msg['To']      = to_addr
        msg['Subject'] = subject
        if orig_msg_id:
            msg['In-Reply-To'] = orig_msg_id
        if references:
            msg['References'] = references

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(
            userId='me',
            body={'raw': raw, 'threadId': thread_id}
        ).execute()

        return jsonify({'success': True, 'message': 'Réponse envoyée avec succès'})

    except HttpError as e:
        err_str = str(e)
        if 'insufficientPermissions' in err_str or 'ACCESS_DENIED' in err_str:
            return jsonify({
                'error': "Permission insuffisante. Reconnectez Gmail pour activer l'envoi.",
                'reconnect': True
            }), 403
        print(f"[REPLY] HttpError: {e}")
        return jsonify({'error': f'Erreur envoi: {err_str}'}), 500
    except Exception as e:
        print(f"[REPLY] Error: {e}")
        return jsonify({'error': f'Erreur envoi: {str(e)}'}), 500


@app.route('/api/whatsapp/webhook', methods=['POST'])
def whatsapp_webhook():
    """Webhook Green API — l'utilisateur répond à une notif WhatsApp → on envoie le reply Gmail."""
    try:
        data         = request.get_json(silent=True) or {}
        type_webhook = data.get('typeWebhook', '')

        if type_webhook != 'incomingMessageReceived':
            return jsonify({'status': 'ignored'}), 200

        msg_data = data.get('messageData', {})
        if msg_data.get('typeMessage') != 'textMessage':
            return jsonify({'status': 'not_text'}), 200

        reply_text = msg_data.get('textMessageData', {}).get('textMessage', '').strip()
        if not reply_text:
            return jsonify({'status': 'empty'}), 200

        # On ne traite que les réponses à une notif (quotedMessage présent)
        quoted = msg_data.get('quotedMessage')
        if not quoted:
            return jsonify({'status': 'not_a_reply'}), 200

        original_wa_msg_id = quoted.get('stanzaId', '')
        if not original_wa_msg_id:
            return jsonify({'status': 'no_stanza_id'}), 200

        # Retrouver l'email Gmail correspondant
        db  = get_db()
        row = None
        try:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT user_email, gmail_message_id FROM whatsapp_email_map WHERE wa_msg_id=%s",
                    (original_wa_msg_id,)
                )
                row = cur.fetchone()
        finally:
            _return_db(db)

        if not row:
            print(f"[WEBHOOK] Aucun mapping pour wa_msg_id={original_wa_msg_id}")
            return jsonify({'status': 'no_mapping'}), 200

        user_email       = row['user_email']
        gmail_message_id = row['gmail_message_id']

        service = _get_gmail_service(user_email)
        if not service:
            print(f"[WEBHOOK] Gmail non connecté pour {user_email}")
            return jsonify({'status': 'gmail_not_connected'}), 200

        orig  = service.users().messages().get(
            userId='me', id=gmail_message_id, format='metadata',
            metadataHeaders=['Subject', 'From', 'Message-ID', 'References']
        ).execute()
        hdrs      = {h['name']: h['value'] for h in orig.get('payload', {}).get('headers', [])}
        thread_id = orig.get('threadId', '')
        subject   = hdrs.get('Subject', '')
        if not subject.lower().startswith('re:'):
            subject = f'Re: {subject}'
        to_addr      = hdrs.get('From', '')
        orig_msg_id  = hdrs.get('Message-ID', '')
        existing_refs = hdrs.get('References', '')
        references   = (f'{existing_refs} {orig_msg_id}').strip() if orig_msg_id else existing_refs

        msg = MIMEText(reply_text, 'plain', 'utf-8')
        msg['To']      = to_addr
        msg['Subject'] = subject
        if orig_msg_id:
            msg['In-Reply-To'] = orig_msg_id
        if references:
            msg['References'] = references

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(
            userId='me',
            body={'raw': raw, 'threadId': thread_id}
        ).execute()

        print(f"[WEBHOOK] Reply WhatsApp envoyé → {to_addr} pour {user_email}")

        # Confirmation WhatsApp à l'expéditeur
        sender_chat_id = data.get('senderData', {}).get('chatId', '')
        if sender_chat_id and GREEN_API_INSTANCE and GREEN_API_TOKEN:
            try:
                confirm_url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/sendMessage/{GREEN_API_TOKEN}"
                requests.post(confirm_url, json={
                    "chatId": sender_chat_id,
                    "message": f"✅ Réponse envoyée à {to_addr} !"
                }, timeout=10)
            except Exception:
                pass

        return jsonify({'status': 'reply_sent'}), 200

    except Exception as e:
        print(f"[WEBHOOK] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/analyze')
@token_required
def ai_analyze():
    """Analyse la boîte mail de l'utilisateur avec Claude et retourne un résumé IA."""
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({"error": "email requis"}), 400

    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    if not GEMINI_API_KEY:
        return jsonify({"error": "GEMINI_API_KEY manquant"}), 503

    # Cache 5 min — évite les 429 Gemini sous charge
    cache_key = f"ai_analyze:{email}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    try:
        service = _get_gmail_service(email)
        if not service:
            return jsonify({"error": "Gmail non connecté"}), 403

        result = service.users().messages().list(
            userId='me', labelIds=['INBOX'], maxResults=10
        ).execute()
        msg_ids = [m['id'] for m in result.get('messages', [])]

        emails_data = []
        for msg_id in msg_ids:
            try:
                msg  = service.users().messages().get(
                    userId='me', id=msg_id, format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date'],
                ).execute()
                hdrs    = {h['name']: h['value'] for h in msg.get('payload', {}).get('headers', [])}
                subject = hdrs.get('Subject', '(Sans objet)')[:120]
                sender  = hdrs.get('From', 'Inconnu')[:100]
                snippet = msg.get('snippet', '')[:200]
                unread  = 'UNREAD' in msg.get('labelIds', [])
                emails_data.append({
                    "id": msg_id, "subject": subject,
                    "sender": sender, "snippet": snippet, "unread": unread,
                })
            except Exception:
                continue

        if not emails_data:
            return jsonify({
                "summary": "Aucun email trouvé dans la boîte mail.",
                "urgent_count": 0, "important_count": 0,
                "newsletter_count": 0, "normal_count": 0,
                "actions": [], "emails": [],
            })

        emails_text = "\n".join(
            f"[{i+1}] ID:{e['id']} | De: {e['sender']} | Objet: {e['subject']} | "
            f"{'NON LU' if e['unread'] else 'Lu'} | Apercu: {e['snippet']}"
            for i, e in enumerate(emails_data)
        )

        prompt = f"""Tu es un assistant IA de gestion d'emails. Analyse ces {len(emails_data)} emails récents et réponds UNIQUEMENT en JSON valide, sans texte avant ni après.

EMAILS:
{emails_text}

Réponds avec ce JSON exact:
{{
  "summary": "Résumé de 2 phrases max de l'état de la boîte mail",
  "urgent_count": <nombre d'emails urgents/importants>,
  "important_count": <nombre d'emails importants>,
  "newsletter_count": <nombre de newsletters/promotions>,
  "normal_count": <nombre d'emails normaux>,
  "actions": ["action1 concrète à faire", "action2"],
  "emails": [
    {{"id": "<id>", "category": "important|newsletter|normal", "reason": "raison courte en français", "priority": "high|medium|low"}}
  ]
}}

Règles de classification:
- important: factures, paiements, sécurité, urgences, réunions, contrats, mots de passe, alertes compte
- newsletter: promotions, publicités, désabonnement, marketing, offres commerciales
- normal: tout le reste (emails de collègues, notifications informatives, etc.)"""

        GEMINI_MODELS = [
            'gemini-2.0-flash-lite',
            'gemini-1.5-flash',
        ]

        import json as _json_ai

        resp = None
        last_err = None
        for model_name in GEMINI_MODELS:
            url = (
                'https://generativelanguage.googleapis.com/v1beta/models/'
                f'{model_name}:generateContent?key={GEMINI_API_KEY}'
            )
            try:
                resp = requests.post(
                    url,
                    headers={'Content-Type': 'application/json'},
                    json={
                        'contents': [{'role': 'user', 'parts': [{'text': prompt}]}],
                        'generationConfig': {'maxOutputTokens': 1500, 'temperature': 0.2},
                    },
                    timeout=(5, 45),
                )
                resp.raise_for_status()
                break
            except Exception as e:
                last_err = e
                resp = None
                continue

        if resp is None:
            raise last_err

        raw = resp.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        # Strip markdown code fences if present
        if '```' in raw:
            parts = raw.split('```')
            # parts[1] is the content between first and second fence
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith('json'):
                raw = raw[4:]
            raw = raw.strip()
        analysis = _json_ai.loads(raw)
        _cache_set(cache_key, analysis, ttl=300)   # 5 min
        return jsonify(analysis)

    except Exception as e:
        print(f"[AI] Erreur analyse: {e}")
        return jsonify({"error": f"Erreur analyse IA: {str(e)}"}), 500


@app.route('/api/stats')
@token_required
def get_stats():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({"total_messages": 0, "unread_count": 0, "email": email})

    cache_key = f"stats:{email}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

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

        result = {"total_messages": total, "unread_count": unread, "email": email}
        _cache_set(cache_key, result, ttl=30)
        return jsonify(result)
    except Exception as e:
        print(f"[ERROR] get_stats: {e}")
        return jsonify({"total_messages": 0, "unread_count": 0, "email": email})


# ─── USER SETTINGS ────────────────────────────────────────────────────────────

@app.route('/api/user/whatsapp-check', methods=['GET'])
def whatsapp_check_number():
    """Vérifie si un numéro est sur WhatsApp via checkWhatsapp."""
    phone = (request.args.get('phone') or '').strip()
    if not phone:
        return jsonify({"error": "phone requis"}), 400
    if not GREEN_API_INSTANCE or not GREEN_API_TOKEN:
        return jsonify({"error": "WhatsApp non configuré"}), 503
    phone_clean = re.sub(r'\D', '', phone)
    try:
        url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/checkWhatsapp/{GREEN_API_TOKEN}"
        resp = requests.post(url, json={"phoneNumber": phone_clean}, timeout=10)
        if resp.ok and resp.text.strip():
            data = resp.json()
            exists = data.get('existsWhatsapp', False)
            chat_id = data.get('chatId', '') if exists else ''
            return jsonify({"exists": exists, "chatId": chat_id, "phone": phone_clean})
        return jsonify({"exists": False, "chatId": "", "phone": phone_clean})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/user/whatsapp-qr', methods=['GET'])
def get_whatsapp_qr():
    if not GREEN_API_INSTANCE or not GREEN_API_TOKEN:
        return jsonify({"error": "WhatsApp non configuré sur ce serveur"}), 503
    url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/qr/{GREEN_API_TOKEN}"
    try:
        resp = requests.get(url, timeout=15)
        if not resp.ok:
            return jsonify({"error": f"Erreur Green API: {resp.status_code}"}), 502
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/user/avatar', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def upload_avatar():
    """Upload avatar vers Cloudinary et sauvegarde l'URL en DB."""
    email = request.current_user['email']

    if not _cloudinary_enabled:
        return jsonify({'error': 'Cloudinary non configuré sur ce serveur'}), 503

    if 'file' not in request.files:
        return jsonify({'error': 'Fichier requis (champ "file")'}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'Fichier vide'}), 400

    allowed_types = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}
    if file.content_type not in allowed_types:
        return jsonify({'error': 'Format non supporté (jpg, png, webp, gif)'}), 415

    # Limite à 5 Mo
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > 5 * 1024 * 1024:
        return jsonify({'error': 'Fichier trop volumineux (max 5 Mo)'}), 413

    try:
        public_id = f"mailnotifier/avatars/{hashlib.md5(email.encode()).hexdigest()}"
        result = cloudinary.uploader.upload(
            file,
            public_id   = public_id,
            overwrite   = True,
            invalidate  = True,
            transformation = [
                {'width': 200, 'height': 200, 'crop': 'fill', 'gravity': 'face', 'quality': 'auto', 'fetch_format': 'auto'}
            ],
        )
        url = result['secure_url']

        db = get_db()
        try:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE users SET avatar=%s WHERE email=%s AND is_verified=1",
                    (url, email)
                )
            db.commit()
        finally:
            _return_db(db)

        _cache_del(f"settings:{email}")
        print(f"[Cloudinary] Avatar uploadé pour {email} → {url}")
        return jsonify({'url': url})

    except Exception as e:
        print(f"[Cloudinary] Erreur upload pour {email}: {e}")
        return jsonify({'error': 'Erreur lors de l\'upload'}), 500


@app.route('/api/user/settings', methods=['GET'])
@token_required
def get_user_settings():
    email = _str(request.args.get('email'), 150).lower()
    if not _is_valid_email(email):
        return jsonify({"error": "email requis"}), 400
    cache_key = f"settings:{email}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT name, email, phone, gmail_address, telegram_chat_id, green_api_instance, "
                "green_api_token, app_password, avatar, theme_color, font_family, theme_mode, theme_secondary, "
                "to_char(theme_updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS theme_updated_at, "
                "COALESCE(telegram_enabled, TRUE) AS telegram_enabled, "
                "COALESCE(whatsapp_enabled, TRUE) AS whatsapp_enabled "
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
                "theme_secondary": "", "theme_updated_at": None,
                "telegram_enabled": True, "whatsapp_enabled": True
            })
        user = dict(user)
        for key in ["phone", "gmail_address", "telegram_chat_id", "green_api_instance",
                    "green_api_token", "avatar", "theme_color", "font_family",
                    "theme_mode", "theme_secondary"]:
            if user.get(key) is None:
                user[key] = ""
        user['telegram_enabled'] = bool(user.get('telegram_enabled', True))
        user['whatsapp_enabled'] = bool(user.get('whatsapp_enabled', True))
        user['app_password_set'] = bool(user.pop('app_password', None))
        if not user.get('theme_mode'):
            user['theme_mode'] = 'light'
        _cache_set(cache_key, user, 30)
        return jsonify(user)
    finally:
        _return_db(db)


@app.route('/api/user/settings', methods=['PUT'])
@token_required
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
            # COALESCE sur tous les champs critiques — un champ absent dans le body
            # ne doit PAS écraser la valeur existante en base
            def _val(key):
                v = data.get(key)
                return v if v not in (None, '') else None

            # Booléens : False est une valeur valide, on ne peut pas utiliser _val
            def _bool_val(key):
                v = data.get(key)
                return v if isinstance(v, bool) else None

            # Si le numéro de téléphone change → effacer whatsapp_chat_id
            new_phone_raw = _val('phone')
            if new_phone_raw:
                cur.execute("SELECT phone FROM users WHERE email = %s AND is_verified = 1", (email,))
                old_row = cur.fetchone()
                old_phone_clean = re.sub(r'\D', '', old_row.get('phone') or '') if old_row else ''
                new_phone_clean = re.sub(r'\D', '', new_phone_raw)
                if old_phone_clean != new_phone_clean:
                    cur.execute("UPDATE users SET whatsapp_chat_id = NULL WHERE email = %s", (email,))
                    print(f"[Settings] Phone changé ({old_phone_clean}→{new_phone_clean}), whatsapp_chat_id effacé")

            if app_password:
                cur.execute(
                    """UPDATE users SET
                        name             = COALESCE(%s, name),
                        phone            = COALESCE(%s, phone),
                        gmail_address    = COALESCE(%s, gmail_address),
                        telegram_chat_id = COALESCE(%s, telegram_chat_id),
                        green_api_instance = COALESCE(%s, green_api_instance),
                        green_api_token  = COALESCE(%s, green_api_token),
                        app_password     = %s,
                        avatar           = COALESCE(%s, avatar),
                        theme_color      = COALESCE(%s, theme_color),
                        font_family      = COALESCE(%s, font_family),
                        theme_mode       = COALESCE(%s, theme_mode),
                        theme_secondary  = COALESCE(%s, theme_secondary),
                        theme_updated_at = CASE WHEN %s THEN NOW() ELSE theme_updated_at END,
                        telegram_enabled = COALESCE(%s, telegram_enabled),
                        whatsapp_enabled = COALESCE(%s, whatsapp_enabled)
                    WHERE email = %s AND is_verified = 1""",
                    (name, _val('phone'), _val('gmail_address'),
                     _val('telegram_chat_id'), _val('green_api_instance'),
                     _val('green_api_token'), app_password,
                     avatar, theme_color, font_family, theme_mode, theme_secondary,
                     bool(theme_color or font_family or theme_mode or theme_secondary),
                     _bool_val('telegram_enabled'), _bool_val('whatsapp_enabled'),
                     email)
                )
            else:
                cur.execute(
                    """UPDATE users SET
                        name             = COALESCE(%s, name),
                        phone            = COALESCE(%s, phone),
                        gmail_address    = COALESCE(%s, gmail_address),
                        telegram_chat_id = COALESCE(%s, telegram_chat_id),
                        green_api_instance = COALESCE(%s, green_api_instance),
                        green_api_token  = COALESCE(%s, green_api_token),
                        avatar           = COALESCE(%s, avatar),
                        theme_color      = COALESCE(%s, theme_color),
                        font_family      = COALESCE(%s, font_family),
                        theme_mode       = COALESCE(%s, theme_mode),
                        theme_secondary  = COALESCE(%s, theme_secondary),
                        theme_updated_at = CASE WHEN %s THEN NOW() ELSE theme_updated_at END,
                        telegram_enabled = COALESCE(%s, telegram_enabled),
                        whatsapp_enabled = COALESCE(%s, whatsapp_enabled)
                    WHERE email = %s AND is_verified = 1""",
                    (name, _val('phone'), _val('gmail_address'),
                     _val('telegram_chat_id'), _val('green_api_instance'),
                     _val('green_api_token'),
                     avatar, theme_color, font_family, theme_mode, theme_secondary,
                     bool(theme_color or font_family or theme_mode or theme_secondary),
                     _bool_val('telegram_enabled'), _bool_val('whatsapp_enabled'),
                     email)
                )
        db.commit()
        _cache_del(f"settings:{email}")
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


def _resolve_whatsapp_chat_id(phone_clean: str):
    """
    Résout le chatId WhatsApp correct pour un numéro.
    Certains comptes WhatsApp utilisent @lid (nouveau format) au lieu de @c.us.
    """
    try:
        url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/checkWhatsapp/{GREEN_API_TOKEN}"
        resp = requests.post(url, json={"phoneNumber": phone_clean}, timeout=10)
        if resp.ok:
            data = resp.json()
            if data.get('existsWhatsapp'):
                chat_id = data.get('chatId', '')
                if chat_id:
                    return chat_id
                # Fallback @c.us si checkWhatsapp ne retourne pas de chatId
                return f"{phone_clean}@c.us"
    except Exception as e:
        print(f"[Monitor] checkWhatsapp exception: {e}")
    return None


def _send_whatsapp_notification(user, sender: str, subject: str, snippet: str, category: str = 'normal', gmail_message_id: str = ''):
    phone = user.get('phone')
    if not phone or not GREEN_API_INSTANCE or not GREEN_API_TOKEN:
        return
    phone_clean = re.sub(r'\D', '', phone)
    if not phone_clean:
        return
    match = re.match(r'^(.+?)\s*<', sender)
    sender_name = match.group(1).strip().strip('"') if match else sender.split('@')[0]
    cat_labels = {'important': '🔴 Important', 'newsletter': '📢 Newsletter', 'normal': '✉️ Normal'}
    cat_label = cat_labels.get(category, '✉️ Normal')
    text = (
        f"*MailNotifier*\n"
        f"------------------\n"
        f"Nouveau mail — {cat_label}\n\n"
        f"*De :* {sender_name}\n"
        f"*Objet :* {subject}\n"
        f"*Aperçu :* {snippet[:150]}\n\n"
        f"------------------\n"
        f"💬 Répondez à ce message WhatsApp pour répondre directement par email."
    )
    try:
        # Préférer le chatId stocké en BDD (évite checkWhatsapp)
        chat_id = user.get('whatsapp_chat_id') or _resolve_whatsapp_chat_id(phone_clean)
        if not chat_id:
            # Dernier recours : format standard
            chat_id = f"{phone_clean}@c.us"
        url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/sendMessage/{GREEN_API_TOKEN}"
        resp = requests.post(url, json={"chatId": chat_id, "message": text}, timeout=10)
        if resp.ok:
            print(f"[Monitor] WhatsApp OK → {phone_clean} (chatId={chat_id})")
            # Sauvegarder le chatId en BDD si pas encore stocké
            if not user.get('whatsapp_chat_id') and chat_id:
                _save_whatsapp_chat_id(user.get('id'), chat_id)
            # Stocker le mapping wa_msg_id → gmail_message_id pour le webhook reply
            if gmail_message_id:
                wa_msg_id = resp.json().get('idMessage', '')
                if wa_msg_id:
                    _store_whatsapp_email_map(wa_msg_id, user.get('email', ''), gmail_message_id)
        else:
            print(f"[Monitor] WhatsApp erreur: {resp.status_code} {resp.text[:100]}")
    except Exception as e:
        print(f"[Monitor] WhatsApp exception: {e}")


_NEWSLETTER_KEYWORDS = [
    'unsubscribe', 'désabonner', 'newsletter', 'noreply', 'no-reply',
    'do-not-reply', 'donotreply', 'ne pas répondre',
    'publicite', 'publicité', 'soldes', 'réduction', 'discount',
    'marketing', 'promotion', 'deal', 'offre spéciale', 'bon plan',
    'weekly digest', 'monthly digest', 'bulletin mensuel', 'bulletin hebdo',
]
_IMPORTANT_KEYWORDS = [
    'urgent', 'important', 'facture', 'invoice', 'paiement', 'payment',
    'alerte', 'alert', 'sécurité', 'security', 'votre compte', 'your account',
    'action requise', 'action required', 'délai', 'deadline', 'expiration',
    'confirmation', 'virement', 'remboursement', 'refund', 'commande', 'order',
    'rendez-vous', 'appointment', 'contrat', 'contract', 'signature',
    'mot de passe', 'password', 'authentification', 'verification', 'code',
    'incident', 'problème', 'error', 'erreur', 'échec', 'failed',
    'réunion', 'meeting', 'convocation', 'entretien', 'interview',
]
_NEWSLETTER_DOMAINS = [
    'mailchimp', 'sendgrid', 'klaviyo', 'constantcontact', 'hubspot',
    'mailjet', 'sendinblue', 'brevo', 'campaignmonitor', 'aweber',
]

def _classify_email(sender: str, subject: str, snippet: str) -> str:
    sender_l  = sender.lower()
    subject_l = subject.lower()
    text      = f"{sender_l} {subject_l} {snippet.lower()}"

    # Newsletter: sender domain or keywords
    if any(d in sender_l for d in _NEWSLETTER_DOMAINS):
        return 'newsletter'
    if any(k in text for k in _NEWSLETTER_KEYWORDS):
        return 'newsletter'
    # Important: keywords in subject (higher weight) or text
    if any(k in subject_l for k in _IMPORTANT_KEYWORDS):
        return 'important'
    if any(k in text for k in _IMPORTANT_KEYWORDS):
        return 'important'
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


def _send_telegram_notification(chat_id, sender, subject, snippet, user_email, category='normal'):
    if not TELEGRAM_BOT_TOKEN:
        print("[Monitor] TELEGRAM_BOT_TOKEN manquant — notification ignoree")
        return
    match = re.match(r'^(.+?)\s*<', sender)
    sender_name = match.group(1).strip().strip('"') if match else sender.split('@')[0]
    cat_labels = {
        'important':  '🔴 *Important*',
        'newsletter': '🟡 Newsletter',
        'normal':     '🔵 Normal',
    }
    cat_label = cat_labels.get(category, '🔵 Normal')
    text = (
        f"📬 *MailNotifier*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Nouveau mail reçu — {cat_label}\n\n"
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


def _save_whatsapp_chat_id(user_id, chat_id: str):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET whatsapp_chat_id=%s WHERE id=%s", (chat_id, user_id))
        db.commit()
    except Exception as e:
        print(f"[Monitor] Erreur save whatsapp_chat_id: {e}")
    finally:
        _return_db(db)


def _store_whatsapp_email_map(wa_msg_id: str, user_email: str, gmail_message_id: str):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO whatsapp_email_map (wa_msg_id, user_email, gmail_message_id)
                   VALUES (%s, %s, %s) ON CONFLICT (wa_msg_id) DO NOTHING""",
                (wa_msg_id, user_email, gmail_message_id)
            )
        db.commit()
    except Exception as e:
        print(f"[Monitor] Erreur store whatsapp_email_map: {e}")
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

                    if chat_id and user.get('telegram_enabled', True):
                        _send_telegram_notification(chat_id, sender, subject, snippet, user_email, category)

                    if user.get('whatsapp_enabled', True):
                        _send_whatsapp_notification(user, sender, subject, snippet, category, gmail_message_id=msg_id)

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
            err_str = str(e).lower()
            if any(x in err_str for x in ['invalid starthistoryid', 'requested entity was not found', 'invalid history id', '404']):
                print(f"[Monitor] historyId expiré pour {user_email}, réinitialisation → {current_history_id}")
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
                       fcm_token, phone, whatsapp_chat_id,
                       COALESCE(telegram_enabled, TRUE) AS telegram_enabled,
                       COALESCE(whatsapp_enabled, TRUE) AS whatsapp_enabled
                FROM users
                WHERE gmail_refresh_token IS NOT NULL
                  AND (
                    (telegram_chat_id IS NOT NULL AND telegram_chat_id != '')
                    OR fcm_token IS NOT NULL
                    OR (phone IS NOT NULL AND phone != '')
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


@app.route('/api/whatsapp/test')
def whatsapp_test():
    """Endpoint de diagnostic WhatsApp — teste le flux complet pour un user."""
    email = request.args.get('email', '').strip().lower()
    logs  = []

    logs.append(f"GREEN_API_URL      = {GREEN_API_URL}")
    logs.append(f"GREEN_API_INSTANCE = {'SET' if GREEN_API_INSTANCE else 'MANQUANT'}")
    logs.append(f"GREEN_API_TOKEN    = {'SET' if GREEN_API_TOKEN else 'MANQUANT'}")

    if not GREEN_API_INSTANCE or not GREEN_API_TOKEN:
        logs.append("ERREUR : variables GREEN_API non configurées sur Render !")
        return jsonify({"logs": logs}), 503

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT phone, whatsapp_chat_id FROM users WHERE email = %s AND is_verified = 1", (email,))
            row = cur.fetchone()
    finally:
        _return_db(db)

    if not row:
        logs.append(f"ERREUR: utilisateur {email} non trouvé")
        return jsonify({"logs": logs}), 404

    phone = (row.get('phone') or '').strip()
    stored_chat_id = (row.get('whatsapp_chat_id') or '').strip()
    logs.append(f"phone en BDD           = '{phone}'")
    logs.append(f"whatsapp_chat_id en BDD = '{stored_chat_id}'")

    if not phone:
        logs.append("ERREUR : numéro de téléphone vide en BDD")
        return jsonify({"logs": logs}), 400

    phone_clean = re.sub(r'\D', '', phone)
    logs.append(f"phone nettoyé          = '{phone_clean}'")

    # Toujours vérifier checkWhatsapp pour diagnostic (même si chatId déjà stocké)
    try:
        check_url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/checkWhatsapp/{GREEN_API_TOKEN}"
        cr = requests.post(check_url, json={"phoneNumber": phone_clean}, timeout=10)
        logs.append(f"checkWhatsapp HTTP     = {cr.status_code}")
        if cr.ok and cr.text.strip():
            cd = cr.json()
            logs.append(f"checkWhatsapp resp     = {cd}")
        else:
            logs.append(f"checkWhatsapp body vide (HTTP {cr.status_code})")
    except Exception as ce:
        logs.append(f"checkWhatsapp exception: {ce}")

    # Utiliser le chatId stocké si disponible, sinon tenter checkWhatsapp
    if stored_chat_id:
        chat_id = stored_chat_id
        logs.append(f"chatId (BDD)           = {chat_id}")
    else:
        try:
            check_url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/checkWhatsapp/{GREEN_API_TOKEN}"
            resp = requests.post(check_url, json={"phoneNumber": phone_clean}, timeout=10)
            logs.append(f"checkWhatsapp HTTP     = {resp.status_code}")
            if resp.ok and resp.text.strip():
                cdata = resp.json()
                logs.append(f"checkWhatsapp resp     = {cdata}")
                chat_id = cdata.get('chatId', '') if cdata.get('existsWhatsapp') else f"{phone_clean}@c.us"
            else:
                chat_id = f"{phone_clean}@c.us"
                logs.append(f"checkWhatsapp indispo (HTTP {resp.status_code}), fallback @c.us")
        except Exception as e:
            chat_id = f"{phone_clean}@c.us"
            logs.append(f"checkWhatsapp exception: {e} — fallback @c.us")
        logs.append(f"chatId résolu          = {chat_id}")

    # Envoi message test
    try:
        send_url = f"{GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/sendMessage/{GREEN_API_TOKEN}"
        token_preview = (GREEN_API_TOKEN or '')[:6] + '...' if GREEN_API_TOKEN else 'NONE'
        logs.append(f"sendMessage URL    = {GREEN_API_URL}/waInstance{GREEN_API_INSTANCE}/sendMessage/{token_preview}")
        payload  = {"chatId": chat_id, "message": "MailNotifier - Test automatique WhatsApp reussi !"}
        sresp    = requests.post(send_url, json=payload, timeout=10)
        logs.append(f"sendMessage HTTP   = {sresp.status_code}")
        logs.append(f"sendMessage resp   = {sresp.text[:300]}")
    except Exception as e:
        logs.append(f"ERREUR sendMessage : {e}")

    return jsonify({"logs": logs})


def monitor_emails_loop():
    """Boucle principale : vérifie les nouveaux mails toutes les 30 secondes."""
    print("[Monitor] Surveillance des emails demarree (intervalle 30s)")
    while True:
        try:
            _check_all_users()
        except Exception as e:
            print(f"[Monitor] Erreur boucle: {e}")
            if _sentry_dsn:
                sentry_sdk.capture_exception(e)
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
            print("[WEBSOCKET] Token expiré")
            emit('error', {'message': 'Token expiré'})
            return False
        except jwt.InvalidTokenError:
            print("[WEBSOCKET] Token invalide")
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
        print("[WEBSOCKET] Connexion sans token")
        emit('error', {'message': 'Token requis'})
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Gère la déconnexion WebSocket."""
    print("[WEBSOCKET] Utilisateur déconnecté")

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

@app.route('/api/weekly/test', methods=['POST'])
@token_required
def trigger_weekly_summary():
    """Déclenche manuellement le résumé hebdomadaire pour l'utilisateur connecté (test)."""
    email = request.current_user['email']
    db = None
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT email, name FROM users WHERE email=%s AND is_verified=1", (email,))
            user = cur.fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        threading.Thread(target=_send_weekly_summary_to_user, args=(dict(user),), daemon=True).start()
        return jsonify({'message': f'Résumé en cours d\'envoi à {email}'})
    finally:
        if db:
            _return_db(db)


@app.route('/api/version', methods=['GET'])
def api_version():
    import sys
    routes = [str(r) for r in app.url_map.iter_rules() if 'chatbot' in str(r) or 'version' in str(r)]
    return jsonify({'version': 'v4.3-gemini', 'python': sys.version, 'routes': routes})


@app.route('/api/chatbot', methods=['POST'])
@limiter.limit("30 per hour; 5 per minute")
def chat_bot():
    """Chatbot IA MailNotifier — Gemini 2.5 Flash Lite via REST."""
    data    = request.get_json() or {}
    message = _str(data.get('message', ''), 500).strip()
    history = data.get('history', [])

    if not message:
        return jsonify({'error': 'message requis'}), 400

    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    if not GEMINI_API_KEY:
        return jsonify({'response': (
            "Bonjour ! Je suis l'assistant MailNotifier. \U0001f60a "
            "MailNotifier surveille ta boite Gmail et t'envoie des alertes Telegram et WhatsApp. "
            "Cree ton compte gratuitement en haut de la page !"
        )}), 200

    system_prompt = (
        "Tu es l'assistant virtuel officiel de MailNotifier, une app web de surveillance Gmail avec notifications temps reel.\n\n"
        "PRODUIT:\n"
        "- Surveillance Gmail OAuth2 — nouveau mail detecte en < 30 secondes\n"
        "- Notifications Telegram (gratuit) et WhatsApp (premium)\n"
        "- IA integree: classe chaque email important/newsletter/normal\n"
        "- Dashboard: derniers mails, stats, canaux, analyse IA\n\n"
        "TARIFS:\n"
        "- Gratuit: Gmail + Telegram. Pour toujours.\n"
        "- Premium (5 000 XOF/mois): + WhatsApp + filtres avances\n"
        "- Enterprise (15 000 XOF/mois): + Support prioritaire\n\n"
        "SETUP 3 ETAPES: 1) Inscription email+OTP  2) Connexion Gmail OAuth  3) Chat ID Telegram ou numero WhatsApp\n\n"
        "REGLES: Reponds en francais, concis et chaleureux (2-4 phrases max). "
        "1-2 emojis max. Tu peux repondre a toutes les questions generales (culture, tech, vie quotidienne, etc.). "
        "Quand c'est pertinent, mentionne subtilement MailNotifier. Ne refuse jamais une question."
    )

    # Format Gemini: role "bot" → "model", system_instruction separe
    contents = []
    for h in (history or [])[-6:]:
        role    = h.get('role', '')
        content = _str(h.get('text', ''), 400)
        if role == 'user' and content:
            contents.append({'role': 'user',  'parts': [{'text': content}]})
        elif role == 'bot' and content:
            contents.append({'role': 'model', 'parts': [{'text': content}]})
    contents.append({'role': 'user', 'parts': [{'text': message}]})

    url = (
        'https://generativelanguage.googleapis.com/v1beta/models/'
        f'gemini-2.5-flash-lite:generateContent?key={GEMINI_API_KEY}'
    )

    try:
        resp = requests.post(
            url,
            headers={'Content-Type': 'application/json'},
            json={
                'system_instruction': {'parts': [{'text': system_prompt}]},
                'contents': contents,
                'generationConfig': {'maxOutputTokens': 250, 'temperature': 0.7},
            },
            timeout=(5, 20),
        )
        resp.raise_for_status()
        text = resp.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        return jsonify({'response': text})
    except Exception as e:
        print(f"[Chat] Erreur Gemini: {e}")
        # Capture Sentry uniquement pour les vraies erreurs (pas les 429 attendus)
        if _sentry_dsn and '429' not in str(e) and 'timeout' not in str(e).lower():
            sentry_sdk.capture_exception(e)
        return jsonify({'response': "Desole, erreur momentanee. Reessaie dans un instant !"}), 200


def _send_weekly_summary_to_user(user: dict):
    """Génère et envoie le résumé hebdomadaire à un utilisateur."""
    email     = user['email']
    name      = (user.get('name') or email.split('@')[0]).split()[0]
    try:
        service = _get_gmail_service(email)
        if not service:
            return

        after_date = (datetime.now() - timedelta(days=7)).strftime('%Y/%m/%d')
        result = service.users().messages().list(
            userId='me', labelIds=['INBOX'],
            q=f'after:{after_date}', maxResults=100
        ).execute()
        messages = result.get('messages', [])
        total = len(messages)
        if total == 0:
            return

        unread = 0
        senders: list[str] = []
        subjects_preview: list[str] = []

        for msg_data in messages[:25]:
            try:
                msg = service.users().messages().get(
                    userId='me', id=msg_data['id'],
                    format='metadata',
                    metadataHeaders=['From', 'Subject']
                ).execute()
                hdrs = {h['name']: h['value'] for h in msg.get('payload', {}).get('headers', [])}
                if 'UNREAD' in msg.get('labelIds', []):
                    unread += 1
                from_h = hdrs.get('From', '')
                m = re.search(r'"?([^"<@]+)"?\s*<?[^>]*>?', from_h)
                sname = m.group(1).strip().strip('"') if m else from_h.split('@')[0]
                if sname and sname not in senders:
                    senders.append(sname)
                subj = hdrs.get('Subject', '(Sans objet)')[:60]
                if len(subjects_preview) < 5:
                    subjects_preview.append(subj)
            except Exception:
                pass

        read_count     = total - unread
        week_start     = (datetime.now() - timedelta(days=7)).strftime('%d %b')
        week_end       = datetime.now().strftime('%d %b %Y')
        top_senders    = ', '.join(senders[:5]) or '—'

        # Taux de lecture
        read_pct = int(read_count / total * 100) if total else 0

        subjects_html = ''.join(
            f'<li style="padding:4px 0;color:#475569;font-size:13px;">📧 {s}</li>'
            for s in subjects_preview
        )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0f4ff;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4ff;padding:40px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:20px;overflow:hidden;box-shadow:0 8px 40px rgba(79,70,229,0.12);">

  <!-- HEADER -->
  <tr><td style="background:linear-gradient(135deg,#4f46e5,#7c3aed,#ec4899);padding:36px 40px;text-align:center;">
    <div style="font-size:32px;margin-bottom:8px;">📊</div>
    <h1 style="margin:0;color:white;font-size:24px;font-weight:800;">Ton résumé de la semaine</h1>
    <p style="margin:8px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">{week_start} — {week_end}</p>
  </td></tr>

  <!-- GREETING -->
  <tr><td style="padding:32px 40px 0;">
    <p style="margin:0;font-size:16px;color:#0f172a;">Salut <strong>{name}</strong> 👋</p>
    <p style="color:#64748b;font-size:14px;margin:8px 0 0;">
      Voici un aperçu de ta boîte Gmail pour la semaine écoulée.
    </p>
  </td></tr>

  <!-- STATS -->
  <tr><td style="padding:24px 40px;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td width="33%" style="text-align:center;background:#f8faff;border-radius:14px;padding:20px 12px;border:1px solid #e2e8f0;">
          <div style="font-size:32px;font-weight:800;color:#4f46e5;">{total}</div>
          <div style="font-size:12px;color:#64748b;margin-top:4px;">Emails reçus</div>
        </td>
        <td width="4%"></td>
        <td width="30%" style="text-align:center;background:#f8faff;border-radius:14px;padding:20px 12px;border:1px solid #e2e8f0;">
          <div style="font-size:32px;font-weight:800;color:#ec4899;">{unread}</div>
          <div style="font-size:12px;color:#64748b;margin-top:4px;">Non lus</div>
        </td>
        <td width="4%"></td>
        <td width="29%" style="text-align:center;background:#f8faff;border-radius:14px;padding:20px 12px;border:1px solid #e2e8f0;">
          <div style="font-size:32px;font-weight:800;color:#059669;">{read_count}</div>
          <div style="font-size:12px;color:#64748b;margin-top:4px;">Lus</div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- LECTURE BAR -->
  <tr><td style="padding:0 40px 24px;">
    <p style="margin:0 0 8px;font-size:13px;color:#64748b;">Taux de lecture : <strong style="color:#4f46e5;">{read_pct}%</strong></p>
    <div style="background:#e2e8f0;border-radius:8px;height:8px;overflow:hidden;">
      <div style="background:linear-gradient(90deg,#4f46e5,#7c3aed);height:8px;width:{read_pct}%;border-radius:8px;"></div>
    </div>
  </td></tr>

  <!-- TOP SENDERS -->
  <tr><td style="padding:0 40px 24px;">
    <div style="background:#faf5ff;border-radius:14px;padding:20px;border:1px solid #e9d5ff;">
      <p style="margin:0 0 8px;font-size:13px;font-weight:700;color:#7c3aed;">🏆 Expéditeurs fréquents</p>
      <p style="margin:0;font-size:13px;color:#475569;">{top_senders}</p>
    </div>
  </td></tr>

  <!-- APERÇU SUJETS -->
  {'<tr><td style="padding:0 40px 28px;"><div style="background:#f8faff;border-radius:14px;padding:20px;border:1px solid #e2e8f0;"><p style="margin:0 0 12px;font-size:13px;font-weight:700;color:#4f46e5;">📬 Derniers sujets</p><ul style="margin:0;padding-left:16px;">' + subjects_html + '</ul></div></td></tr>' if subjects_preview else ''}

  <!-- CTA -->
  <tr><td style="padding:0 40px 36px;text-align:center;">
    <a href="https://bs-mailnotif-nine.vercel.app/dashboard"
       style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#4f46e5,#7c3aed);color:white;text-decoration:none;border-radius:12px;font-weight:700;font-size:15px;">
      Voir mon dashboard →
    </a>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="background:#f8faff;padding:20px 40px;text-align:center;border-top:1px solid #e2e8f0;">
    <p style="margin:0;font-size:12px;color:#94a3b8;">
      MailNotifier — Tu reçois ce mail car tu as activé les résumés hebdomadaires.<br>
      © 2025 MailNotifier
    </p>
  </td></tr>

</table></td></tr></table>
</body></html>"""

        msg_email = MIMEMultipart('alternative')
        msg_email['Subject'] = f'📊 Résumé MailNotifier — semaine du {week_start}'
        msg_email['From']    = f'MailNotifier <{SMTP_EMAIL}>'
        msg_email['To']      = email
        msg_email.attach(MIMEText(html, 'html'))

        ctx = create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=ctx) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, email, msg_email.as_string())
        print(f"[WEEKLY] Résumé envoyé → {email} ({total} emails, {unread} non lus)")

    except Exception as e:
        print(f"[WEEKLY] Erreur pour {email}: {e}")


def _send_weekly_summaries():
    """Récupère tous les utilisateurs Gmail connectés et envoie leur résumé."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("[WEEKLY] SMTP non configuré — résumés annulés")
        return
    db = None
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT email, name FROM users "
                "WHERE is_verified = 1 AND gmail_access_token IS NOT NULL"
            )
            users = [dict(u) for u in cur.fetchall()]
        print(f"[WEEKLY] {len(users)} utilisateurs à notifier")
        for idx, u in enumerate(users):
            threading.Thread(
                target=_send_weekly_summary_to_user,
                args=(u,), daemon=True
            ).start()
            time.sleep(1.5)   # espacement pour éviter les rate limits SMTP
    except Exception as e:
        print(f"[WEEKLY] Erreur récupération users: {e}")
    finally:
        if db:
            _return_db(db)


def _weekly_summary_loop():
    """Vérifie chaque heure si c'est lundi 8h UTC pour envoyer les résumés."""
    time.sleep(180)   # laisse le serveur finir son boot
    last_sent_week = -1
    while True:
        try:
            now          = datetime.utcnow()
            current_week = now.isocalendar()[1]
            if now.weekday() == 0 and now.hour == 8 and last_sent_week != current_week:
                last_sent_week = current_week
                print("[WEEKLY] C'est lundi 8h — envoi des résumés hebdomadaires...")
                threading.Thread(target=_send_weekly_summaries, daemon=True).start()
        except Exception as e:
            print(f"[WEEKLY LOOP] Erreur: {e}")
        time.sleep(3600)   # vérifie toutes les heures


def _self_ping_loop():
    """Ping /api/version toutes les 10 min pour garder Render éveillé."""
    time.sleep(60)   # laisse le serveur finir son boot
    base_url = os.getenv('RENDER_EXTERNAL_URL', '')
    if not base_url:
        print("[PING] RENDER_EXTERNAL_URL non défini — self-ping désactivé")
        return
    url = f"{base_url.rstrip('/')}/api/version"
    while True:
        try:
            r = requests.get(url, timeout=10)
            print(f"[PING] self-ping → {r.status_code}")
        except Exception as e:
            print(f"[PING] self-ping error: {e}")
        time.sleep(600)   # 10 minutes


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
        print("[STARTUP] Lancement thread self-ping (anti-sleep Render)...")
        threading.Thread(target=_self_ping_loop, daemon=True, name="self-ping").start()
        print("[STARTUP] Lancement thread résumé hebdomadaire...")
        threading.Thread(target=_weekly_summary_loop, daemon=True, name="weekly-summary").start()
        print("[STARTUP] Tous les threads lances avec succes.")
    except Exception as e:
        import traceback
        print(f"[STARTUP] ERREUR CRITIQUE: {e}")
        traceback.print_exc()

_startup()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
