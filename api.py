print("=== MailNotifier API v3.0 - MONITOR ACTIF ===")
import os
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
from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    return '', 200

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'client_secret_566087061726-dvbm61gi2hkinu2eapo26iikrpr5johp.apps.googleusercontent.com.json'

oauth_pending = {}  # state -> {email, user_id, flow}


def get_credentials_path():
    """Charge le client secret depuis GOOGLE_CLIENT_SECRET_JSON (Render/prod)
    ou depuis le fichier local (dev)."""
    secret_env = os.getenv('GOOGLE_CLIENT_SECRET_JSON')
    if secret_env:
        path = '/tmp/client_secret.json'
        with open(path, 'w') as f:
            f.write(secret_env)
        return path
    return CREDENTIALS_FILE

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

def get_db():
    return psycopg2.connect(
        host=os.getenv('DB_HOST'),
        port=int(os.getenv('DB_PORT', 5432)),
        user=os.getenv('DB_USER', 'avnadmin'),
        password=os.getenv('DB_PASSWORD'),
        dbname=os.getenv('DB_NAME', 'defaultdb'),
        sslmode='require',
        cursor_factory=psycopg2.extras.RealDictCursor
    )

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
        db.close()


# ─── TOKEN HELPERS (DB) ───────────────────────────────────────────────────────

def save_token_to_db(user_id, credentials_json):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET gmail_token=%s WHERE id=%s", (credentials_json, user_id))
        db.commit()
    finally:
        db.close()

def load_token_from_db(user_id):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT gmail_token FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
        return row['gmail_token'] if row and row.get('gmail_token') else None
    finally:
        db.close()


# ─── UTILS ────────────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_otp_email(to_email, name, otp_code):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'Votre code de verification MailNotifier : {otp_code}'
    msg['From']    = SMTP_EMAIL
    msg['To']      = to_email

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f5f5f5;border-radius:16px;">
      <div style="text-align:center;margin-bottom:24px;">
        <h1 style="color:#1a237e;margin:0;">MailNotifier</h1>
        <p style="color:#666;margin:4px 0;">Verification de votre compte</p>
      </div>
      <div style="background:white;border-radius:12px;padding:32px;text-align:center;">
        <p style="color:#333;font-size:16px;">Bonjour <strong>{name}</strong>,</p>
        <p style="color:#555;font-size:14px;">Voici votre code de verification :</p>
        <div style="background:#e8eaf6;border-radius:12px;padding:24px;margin:24px 0;">
          <span style="font-size:42px;font-weight:900;letter-spacing:12px;color:#1a237e;">{otp_code}</span>
        </div>
        <p style="color:#888;font-size:13px;">Ce code expire dans <strong>10 minutes</strong>.</p>
        <p style="color:#bbb;font-size:12px;">Si vous n'avez pas fait cette demande, ignorez cet email.</p>
      </div>
    </div>
    """
    msg.attach(MIMEText(html, 'html'))
    ctx = create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=ctx) as server:
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())


# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data           = request.json
    name           = data.get('name', '').strip()
    email          = data.get('email', '').strip().lower()
    password       = data.get('password', '')
    phone          = data.get('phone', '').strip()
    gmail_address  = data.get('gmail_address', '').strip().lower()
    telegram_chat_id = data.get('telegram_chat_id', '').strip()
    green_api_instance = data.get('green_api_instance', '').strip()
    green_api_token    = data.get('green_api_token', '').strip()

    if not name or not email or not password:
        return jsonify({'error': 'Nom, email et mot de passe requis'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (min 6 caracteres)'}), 400

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
        db.close()

    def send_async():
        try:
            send_otp_email(email, name, otp_code)
        except Exception as e:
            print(f"[SMTP ERREUR] {e}")

    threading.Thread(target=send_async, daemon=True).start()
    return jsonify({'message': f'Code OTP envoye a {email}'}), 200


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data  = request.json
    email = data.get('email', '').strip().lower()
    code  = data.get('code', '').strip()

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
        db.close()


@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.json
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email et mot de passe requis'}), 400

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

        if not user or user['password'] != hash_password(password):
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

        return jsonify({'message': 'Connexion reussie', 'name': user['name'], 'email': email, 'role': user.get('role', 'user')}), 200
    finally:
        db.close()


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
        db.close()


@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, name, email, is_verified, role, plan, phone,
                       gmail_address, telegram_chat_id, green_api_instance,
                       CASE WHEN gmail_token IS NOT NULL THEN TRUE ELSE FALSE END as gmail_connected,
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
        db.close()


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
        db.close()


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        return jsonify({'message': 'Utilisateur supprime'}), 200
    finally:
        db.close()


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
        db.close()


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
        db.close()


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
        db.close()


@app.route('/api/admin/payments/<int:pay_id>', methods=['DELETE'])
def admin_delete_payment(pay_id):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM payments WHERE id=%s", (pay_id,))
        db.commit()
        return jsonify({'message': 'Paiement supprime'}), 200
    finally:
        db.close()


# ─── GMAIL OAUTH2 WEB FLOW ────────────────────────────────────────────────────

@app.route('/api/auth/gmail-connect')
def gmail_connect():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'email requis'}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s AND is_verified = 1", (email,))
            user = cur.fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404
    finally:
        db.close()

    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    base_url     = os.getenv('APP_BASE_URL', 'http://localhost:5000').rstrip('/')
    redirect_uri = f'{base_url}/api/auth/gmail-callback'

    flow = Flow.from_client_secrets_file(
        get_credentials_path(), SCOPES, redirect_uri=redirect_uri
    )
    auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    oauth_pending[state] = {'email': email, 'user_id': user['id'], 'flow': flow}
    return jsonify({'auth_url': auth_url})


@app.route('/api/auth/gmail-callback')
def gmail_callback():
    state        = request.args.get('state')
    error        = request.args.get('error')
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:4200').rstrip('/')

    if error:
        return redirect(f'{frontend_url}/dashboard?gmail=error&msg={error}')
    if not state or state not in oauth_pending:
        return redirect(f'{frontend_url}/dashboard?gmail=error&msg=session_invalid')

    pending = oauth_pending.pop(state)
    flow    = pending['flow']
    try:
        base_url          = os.getenv('APP_BASE_URL', 'http://localhost:5000').rstrip('/')
        flow.redirect_uri = f'{base_url}/api/auth/gmail-callback'
        flow.fetch_token(code=request.args.get('code'))
        save_token_to_db(pending['user_id'], flow.credentials.to_json())
        print(f"[OAuth2] Token sauvegarde en DB pour user_id={pending['user_id']}")
    except Exception as e:
        print(f"[OAuth2] Erreur: {e}")
        return redirect(f'{frontend_url}/dashboard?gmail=error&msg=token_failed')

    return redirect(f'{frontend_url}/dashboard?gmail=connected')


@app.route('/api/auth/gmail-status')
def gmail_status():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'connected': False}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id, gmail_token FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
        if not user:
            return jsonify({'connected': False})
        return jsonify({'connected': bool(user.get('gmail_token'))})
    finally:
        db.close()


# ─── GMAIL ROUTES ─────────────────────────────────────────────────────────────

def get_gmail_service_for(email):
    """Retourne le service Gmail pour un utilisateur donné via son token en DB."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
        if not user:
            return None
        user_id = user['id']
    finally:
        db.close()

    token_json = load_token_from_db(user_id)
    if not token_json:
        return None

    creds = Credentials.from_authorized_user_info(_json.loads(token_json), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            save_token_to_db(user_id, creds.to_json())
        else:
            return None
    return build('gmail', 'v1', credentials=creds)


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
    try:
        service = get_gmail_service_for(email) if email else None
        if not service:
            return jsonify([])
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=20).execute()
        messages = results.get('messages', [])
        emails = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers  = msg_data['payload']['headers']
            subject  = next((h['value'] for h in headers if h['name'] == 'Subject'), '(Sans objet)')
            sender   = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
            date     = next((h['value'] for h in headers if h['name'] == 'Date'), '')
            snippet  = msg_data.get('snippet', '')[:150]
            is_unread = 'UNREAD' in msg_data.get('labelIds', [])
            emails.append({"id": msg['id'], "subject": subject, "sender": sender, "date": date, "snippet": snippet, "unread": is_unread})
        return jsonify(emails)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats')
def get_stats():
    email = request.args.get('email', '').strip().lower()
    try:
        service = get_gmail_service_for(email) if email else None
        if not service:
            return jsonify({"total_messages": 0, "unread_count": 0, "email": email})
        profile = service.users().getProfile(userId='me').execute()
        unread  = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=1).execute()
        return jsonify({
            "total_messages": profile.get('messagesTotal', 0),
            "unread_count": unread.get('resultSizeEstimate', 0),
            "email": profile.get('emailAddress', '')
        })
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
        db.close()


@app.route('/api/user/settings', methods=['GET'])
def get_user_settings():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "email requis"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT name, email, phone, gmail_address, telegram_chat_id, green_api_instance, green_api_token "
                "FROM users WHERE email = %s AND is_verified = 1",
                (email,)
            )
            user = cur.fetchone()
        if not user:
            # Retourne un objet vide plutôt qu'une 404 — l'utilisateur n'a pas encore rempli ses paramètres
            return jsonify({
                "name": "", "email": email, "phone": "",
                "gmail_address": "", "telegram_chat_id": "",
                "green_api_instance": "", "green_api_token": ""
            })
        # Remplace les None par des chaînes vides pour le frontend
        for key in ["phone", "gmail_address", "telegram_chat_id", "green_api_instance", "green_api_token"]:
            if user.get(key) is None:
                user[key] = ""
        return jsonify(user)
    finally:
        db.close()


@app.route('/api/user/settings', methods=['PUT'])
def update_user_settings():
    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        return jsonify({"error": "email requis"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                """UPDATE users SET
                    phone = %s,
                    gmail_address = %s,
                    telegram_chat_id = %s,
                    green_api_instance = %s,
                    green_api_token = %s
                WHERE email = %s AND is_verified = 1""",
                (
                    data.get('phone'),
                    data.get('gmail_address'),
                    data.get('telegram_chat_id'),
                    data.get('green_api_instance'),
                    data.get('green_api_token'),
                    email,
                )
            )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


# ─── EMAIL MONITOR ────────────────────────────────────────────────────────────

import re as _re

def _save_history_id(user_id, history_id):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET last_history_id=%s WHERE id=%s", (history_id, user_id))
        db.commit()
    finally:
        db.close()


def _send_telegram_notification(chat_id, sender, subject, snippet, user_email):
    if not TELEGRAM_BOT_TOKEN:
        print("[Monitor] TELEGRAM_BOT_TOKEN manquant — notification ignoree")
        return
    match = _re.match(r'^(.+?)\s*<', sender)
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


def _check_user_emails(user):
    """Vérifie les nouveaux mails d'un utilisateur via Gmail History API."""
    service = get_gmail_service_for(user['email'])
    if not service:
        return

    user_id       = user['id']
    chat_id       = user['telegram_chat_id']
    last_hist_id  = user.get('last_history_id')

    if not last_hist_id:
        # Premier passage : on enregistre le historyId courant sans notifier
        try:
            profile = service.users().getProfile(userId='me').execute()
            _save_history_id(user_id, str(profile.get('historyId', '')))
            print(f"[Monitor] Init historyId pour {user['email']}")
        except Exception as e:
            print(f"[Monitor] Erreur init historyId {user['email']}: {e}")
        return

    try:
        history_result = service.users().history().list(
            userId='me',
            startHistoryId=last_hist_id,
            historyTypes=['messageAdded'],
            labelId='INBOX'
        ).execute()
    except Exception as e:
        err_str = str(e)
        print(f"[Monitor] History API erreur pour {user['email']}: {err_str}")
        # historyId expiré → réinitialiser
        if '404' in err_str or 'invalid' in err_str.lower():
            try:
                profile = service.users().getProfile(userId='me').execute()
                _save_history_id(user_id, str(profile.get('historyId', '')))
                print(f"[Monitor] historyId reinitialise pour {user['email']}")
            except Exception:
                pass
        return

    new_hist_id = str(history_result.get('historyId', last_hist_id))
    history     = history_result.get('history', [])

    for record in history:
        for msg_added in record.get('messagesAdded', []):
            msg    = msg_added.get('message', {})
            labels = msg.get('labelIds', [])
            if 'INBOX' in labels and 'UNREAD' in labels:
                msg_id = msg['id']
                try:
                    msg_data = service.users().messages().get(
                        userId='me', id=msg_id,
                        format='metadata',
                        metadataHeaders=['Subject', 'From']
                    ).execute()
                    headers  = msg_data['payload']['headers']
                    subject  = next((h['value'] for h in headers if h['name'] == 'Subject'), '(Sans objet)')
                    sender   = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
                    snippet  = msg_data.get('snippet', '')[:200]
                    _send_telegram_notification(chat_id, sender, subject, snippet, user['email'])
                except Exception as e:
                    print(f"[Monitor] Erreur lecture msg {msg_id}: {e}")

    _save_history_id(user_id, new_hist_id)


def _check_all_users():
    """Récupère tous les utilisateurs surveillables et vérifie leurs mails."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, email, telegram_chat_id, last_history_id
                FROM users
                WHERE gmail_token IS NOT NULL
                  AND telegram_chat_id IS NOT NULL
                  AND telegram_chat_id != ''
                  AND is_verified = 1
            """)
            users = [dict(u) for u in cur.fetchall()]
    finally:
        db.close()

    if not users:
        return

    print(f"[Monitor] Verification de {len(users)} utilisateur(s)...")
    for user in users:
        try:
            _check_user_emails(user)
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

@app.route('/api/monitor/test')
def monitor_test():
    """Endpoint de debug : lance un cycle de check et retourne les détails."""
    logs = []

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, email, telegram_chat_id, last_history_id,
                       (gmail_token IS NOT NULL) as has_token
                FROM users WHERE is_verified = 1
            """)
            all_users = [dict(u) for u in cur.fetchall()]
    finally:
        db.close()

    logs.append(f"Total utilisateurs: {len(all_users)}")
    for u in all_users:
        logs.append(
            f"  - {u['email']} | telegram={u['telegram_chat_id']} | "
            f"gmail_token={'OUI' if u['has_token'] else 'NON'} | "
            f"last_history_id={u['last_history_id']}"
        )

    # Utilisateurs éligibles pour la surveillance
    eligible = [u for u in all_users if u['has_token'] and u['telegram_chat_id']]
    logs.append(f"Eligibles (token + telegram): {len(eligible)}")

    for user in eligible:
        service = get_gmail_service_for(user['email'])
        if not service:
            logs.append(f"  ⚠ {user['email']}: service Gmail indisponible (token invalide ?)")
            continue

        if not user['last_history_id']:
            try:
                profile = service.users().getProfile(userId='me').execute()
                hist_id = str(profile.get('historyId', ''))
                _save_history_id(user['id'], hist_id)
                logs.append(f"  ✓ {user['email']}: historyId initialisé à {hist_id}")
            except Exception as e:
                logs.append(f"  ✗ {user['email']}: erreur init historyId: {e}")
            continue

        # Teste l'envoi Telegram directement
        test_text = (
            f"\U0001f4e7 *Test MailNotifier*\n\n"
            f"Le systeme de notification fonctionne correctement !\n"
            f"_Compte surveille : {user['email']}_"
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
