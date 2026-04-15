import os
import time
import threading
import pymysql
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import requests

load_dotenv()

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'client_secret_566087061726-dvbm61gi2hkinu2eapo26iikrpr5johp.apps.googleusercontent.com.json'
TOKENS_DIR = 'tokens'

# Defaults from .env (used as fallback if user has no personal credentials)
DEFAULT_TELEGRAM_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
DEFAULT_TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
DEFAULT_GREEN_API_INSTANCE = os.getenv('GREEN_API_INSTANCE')
DEFAULT_GREEN_API_TOKEN = os.getenv('GREEN_API_TOKEN')
DEFAULT_WHATSAPP_PHONE = os.getenv('WHATSAPP_PHONE')
DEFAULT_GMAIL = os.getenv('GMAIL_ADDRESS')

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'mal_yk'),
    'charset': 'utf8mb4',
}

os.makedirs(TOKENS_DIR, exist_ok=True)


def get_db():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)


def load_users():
    """Charge tous les utilisateurs verifes ayant un gmail_address configure."""
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, email, gmail_address, telegram_chat_id, "
                "green_api_instance, green_api_token, phone "
                "FROM users WHERE is_verified = 1 AND gmail_address IS NOT NULL AND gmail_address != ''"
            )
            users = cur.fetchall()
        conn.close()
        return users
    except Exception as e:
        print(f"[DB] Erreur chargement utilisateurs: {e}")
        return []


def token_file_for(user_id):
    """Retourne le chemin du fichier token pour un utilisateur."""
    # Compatibilite: user_id=1 (admin) peut utiliser token.json a la racine
    legacy = 'token.json'
    dedicated = os.path.join(TOKENS_DIR, f'token_{user_id}.json')
    if os.path.exists(dedicated):
        return dedicated
    if user_id == 1 and os.path.exists(legacy):
        return legacy
    return dedicated  # sera cree lors de l'auth


def get_gmail_service(user):
    """Connexion a Gmail via OAuth2 pour un utilisateur specifique."""
    user_id = user['id']
    token_path = token_file_for(user_id)

    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(token_path, 'w') as f:
                f.write(creds.to_json())
        else:
            print(f"[{user['name']}] Authentification OAuth2 requise pour {user['gmail_address']}")
            print(f"[{user['name']}] Lance le navigateur pour autoriser l'acces...")
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            with open(token_path, 'w') as f:
                f.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


def send_telegram(token, chat_id, message):
    """Envoie une notification Telegram."""
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=10)
        if not resp.ok:
            print(f"[TELEGRAM ERREUR] {resp.status_code}: {resp.text}")
        return resp.ok
    except Exception as e:
        print(f"[TELEGRAM ERREUR] {e}")
        return False


def send_whatsapp(instance, token, phone, message):
    """Envoie une notification WhatsApp via Green API."""
    if not instance or not token or not phone:
        return False
    url = f"https://7107.api.greenapi.com/waInstance{instance}/sendMessage/{token}"
    try:
        resp = requests.post(url, json={"chatId": f"{phone}@c.us", "message": message}, timeout=10)
        if not resp.ok:
            print(f"[WHATSAPP ERREUR] {resp.status_code}: {resp.text}")
        return resp.ok
    except Exception as e:
        print(f"[WHATSAPP ERREUR] {e}")
        return False


def notify_user(user, message):
    """Envoie les notifications Telegram + WhatsApp pour un utilisateur."""
    tg_token = DEFAULT_TELEGRAM_TOKEN
    tg_chat = user.get('telegram_chat_id') or DEFAULT_TELEGRAM_CHAT_ID
    wa_instance = user.get('green_api_instance') or DEFAULT_GREEN_API_INSTANCE
    wa_token = user.get('green_api_token') or DEFAULT_GREEN_API_TOKEN
    wa_phone = user.get('phone') or DEFAULT_WHATSAPP_PHONE

    send_telegram(tg_token, tg_chat, message)
    send_whatsapp(wa_instance, wa_token, wa_phone, message)


def get_email_details(service, msg_id):
    """Recupere l'expediteur, le sujet et un apercu du mail."""
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    headers = msg['payload']['headers']
    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(Sans objet)')
    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
    snippet = msg.get('snippet', '')[:200]
    return sender, subject, snippet


def get_initial_history_id(service):
    profile = service.users().getProfile(userId='me').execute()
    return profile['historyId']


def check_new_emails(service, last_history_id):
    try:
        results = service.users().history().list(
            userId='me',
            startHistoryId=last_history_id,
            historyTypes=['messageAdded'],
            labelId='INBOX'
        ).execute()
        new_history_id = results.get('historyId', last_history_id)
        new_emails = [
            msg['message']['id']
            for change in results.get('history', [])
            for msg in change.get('messagesAdded', [])
        ]
        return new_history_id, new_emails
    except Exception as e:
        print(f"Erreur verification mails: {e}")
        return last_history_id, []


def monitor_user(user, stop_event):
    """Thread de surveillance Gmail pour un utilisateur."""
    name = user['name']
    gmail = user['gmail_address']
    print(f"[{name}] Demarrage surveillance de {gmail}")

    try:
        service = get_gmail_service(user)
    except Exception as e:
        print(f"[{name}] Impossible de se connecter a Gmail: {e}")
        return

    notify_user(user, f"Mail Notifier demarre !\nJe surveille {gmail} pour {name}.")

    try:
        last_history_id = get_initial_history_id(service)
        print(f"[{name}] Surveillance active (History ID: {last_history_id})")
    except Exception as e:
        print(f"[{name}] Erreur recuperation history ID: {e}")
        return

    while not stop_event.is_set():
        try:
            new_history_id, new_email_ids = check_new_emails(service, last_history_id)

            for msg_id in new_email_ids:
                sender, subject, snippet = get_email_details(service, msg_id)
                message = (
                    f"Nouveau Mail pour {name} !\n\n"
                    f"De : {sender}\n"
                    f"Objet : {subject}\n"
                    f"Apercu : {snippet}..."
                )
                notify_user(user, message)
                print(f"[{name}] Notification envoyee : {subject}")

            last_history_id = new_history_id
            stop_event.wait(30)

        except Exception as e:
            print(f"[{name}] Erreur: {e}")
            stop_event.wait(60)

    print(f"[{name}] Surveillance arretee.")


def main():
    print("=== Mail Notifier Multi-Utilisateurs ===")
    print("Chargement des utilisateurs depuis la base de donnees...")

    threads = {}   # user_id -> (thread, stop_event)

    def start_user_thread(user):
        uid = user['id']
        stop = threading.Event()
        t = threading.Thread(target=monitor_user, args=(user, stop), daemon=True, name=f"monitor-{uid}")
        t.start()
        threads[uid] = (t, stop)

    def stop_user_thread(uid):
        if uid in threads:
            t, stop = threads.pop(uid)
            stop.set()

    # Chargement initial
    current_users = {u['id']: u for u in load_users()}
    for user in current_users.values():
        start_user_thread(user)

    if not current_users:
        print("Aucun utilisateur trouve dans la base de donnees.")
        print("En attente de nouveaux utilisateurs (verification toutes les 60s)...")

    print(f"{len(current_users)} utilisateur(s) surveille(s). Ctrl+C pour arreter.\n")

    try:
        while True:
            time.sleep(60)

            # Recharge les utilisateurs pour detecter les nouveaux comptes
            fresh_users = {u['id']: u for u in load_users()}

            # Nouveaux utilisateurs -> demarrer un thread
            for uid, user in fresh_users.items():
                if uid not in threads:
                    print(f"[NOUVEAU] Demarrage surveillance pour {user['name']} ({user['gmail_address']})")
                    start_user_thread(user)

            # Utilisateurs supprimes -> arreter leur thread
            for uid in list(threads.keys()):
                if uid not in fresh_users:
                    print(f"[SUPPRIME] Arret surveillance pour user_id={uid}")
                    stop_user_thread(uid)

            current_users = fresh_users

    except KeyboardInterrupt:
        print("\nArret en cours...")
        for uid in list(threads.keys()):
            stop_user_thread(uid)
        print("Mail Notifier arrete.")


if __name__ == '__main__':
    main()
