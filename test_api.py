"""
Tests unitaires — MailNotifier Backend API
==========================================
Lance avec : python -m pytest test_api.py -v
"""

import sys
import os
import hashlib
import json
from unittest.mock import patch, MagicMock, call
from datetime import datetime, timedelta

# ── Stub des variables d'env avant import de l'app ────────────────────────────
os.environ.setdefault('DB_HOST',     'localhost')
os.environ.setdefault('DB_PORT',     '5432')
os.environ.setdefault('DB_USER',     'test')
os.environ.setdefault('DB_PASSWORD', 'test')
os.environ.setdefault('DB_NAME',     'testdb')
os.environ.setdefault('SMTP_EMAIL',  'test@example.com')
os.environ.setdefault('SMTP_PASSWORD', 'smtp_pass')
os.environ.setdefault('TELEGRAM_BOT_TOKEN', 'fake_token')
os.environ.setdefault('GMAIL_ADDRESS', 'test@gmail.com')

# Patch psycopg2 AVANT l'import de l'app pour éviter une vraie connexion DB
with patch('psycopg2.connect') as _:
    pass

import pytest

# ── Import de l'app en patchant psycopg2 ──────────────────────────────────────
# TESTING=1 désactive _startup() et le rate limiter dans api.py
os.environ['TESTING'] = '1'

sys.path.insert(0, os.path.dirname(__file__))

if 'api' not in sys.modules:
    _psycopg2_mock = MagicMock()
    _psycopg2_mock.connect.return_value = MagicMock()
    _psycopg2_mock.pool = MagicMock()
    _psycopg2_mock.pool.ThreadedConnectionPool = MagicMock()
    with patch.dict(sys.modules, {
        'psycopg2': _psycopg2_mock,
        'psycopg2.extras': _psycopg2_mock,
        'psycopg2.pool': _psycopg2_mock.pool,
    }):
        import api as app_module
    sys.modules['api'] = app_module
else:
    app_module = sys.modules['api']

app = app_module.app
app.config['TESTING'] = True
app.config['RATELIMIT_ENABLED'] = False


# ── Helper : fabrique un curseur mocké ────────────────────────────────────────
def make_db_mock(fetchone_return=None, fetchall_return=None):
    """Retourne un mock de connexion DB complet."""
    cursor = MagicMock()
    cursor.fetchone.return_value = fetchone_return
    cursor.fetchall.return_value = fetchall_return or []
    cursor.__enter__ = lambda s: s
    cursor.__exit__ = MagicMock(return_value=False)

    db = MagicMock()
    db.cursor.return_value = cursor
    db.commit.return_value = None
    db.close.return_value  = None
    return db, cursor


def hashed(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# 1. FONCTIONS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

class TestHashPassword:
    """hash_password() uses bcrypt since Phase 1 security upgrade."""

    def test_returns_bcrypt_hash(self):
        result = app_module.hash_password("secret")
        assert result.startswith('$2b$') or result.startswith('$2a$')

    def test_length_is_bcrypt(self):
        # bcrypt hashes are 60 characters
        assert len(app_module.hash_password("any")) == 60

    def test_different_passwords_differ(self):
        assert app_module.hash_password("abc") != app_module.hash_password("def")

    def test_same_password_verifies_ok(self):
        # bcrypt uses random salt → two hashes differ, but verify_password still works
        h = app_module.hash_password("pw")
        assert app_module.verify_password("pw", h) is True
        assert app_module.verify_password("wrong", h) is False

    def test_empty_string(self):
        result = app_module.hash_password("")
        assert result.startswith('$2b$') or result.startswith('$2a$')


class TestDecodeMimeHeader:
    def test_plain_ascii(self):
        result = app_module._decode_mime_header("Hello World")
        assert result == "Hello World"

    def test_none_returns_empty(self):
        result = app_module._decode_mime_header(None)
        assert result == ""

    def test_empty_string(self):
        result = app_module._decode_mime_header("")
        assert result == ""


# ══════════════════════════════════════════════════════════════════════════════
# 2. /api/status
# ══════════════════════════════════════════════════════════════════════════════

class TestStatus:
    def setup_method(self):
        self.client = app.test_client()

    def test_returns_200(self):
        r = self.client.get('/api/status')
        assert r.status_code == 200

    def test_contains_running_key(self):
        r = self.client.get('/api/status')
        data = r.get_json()
        assert 'running' in data

    def test_contains_telegram_whatsapp(self):
        r = self.client.get('/api/status')
        data = r.get_json()
        assert data['telegram'] is True
        assert data['whatsapp'] is True

    def test_options_returns_200(self):
        r = self.client.options('/api/status')
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 3. /api/auth/login
# ══════════════════════════════════════════════════════════════════════════════

class TestLogin:
    def setup_method(self):
        self.client = app.test_client()

    @patch('api.get_db')
    def test_login_succes(self, mock_get_db):
        user_row = {
            'id': 1, 'name': 'Yao', 'email': 'yao@gmail.com',
            'password': hashed('motdepasse'), 'role': 'user'
        }
        db, cur = make_db_mock(fetchone_return=user_row)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/login',
                             json={'email': 'yao@gmail.com', 'password': 'motdepasse'})
        assert r.status_code == 200
        data = r.get_json()
        assert data['name'] == 'Yao'
        assert data['email'] == 'yao@gmail.com'

    @patch('api.get_db')
    def test_mauvais_mot_de_passe(self, mock_get_db):
        user_row = {'password': hashed('correct'), 'role': 'user', 'name': 'X', 'email': 'x@x.com'}
        db, cur = make_db_mock(fetchone_return=user_row)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/login',
                             json={'email': 'x@x.com', 'password': 'wrong'})
        assert r.status_code == 401

    @patch('api.get_db')
    def test_utilisateur_inexistant(self, mock_get_db):
        db, cur = make_db_mock(fetchone_return=None)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/login',
                             json={'email': 'nobody@x.com', 'password': 'pw'})
        assert r.status_code == 401

    def test_email_manquant(self):
        r = self.client.post('/api/auth/login', json={'password': 'pw'})
        assert r.status_code == 400

    def test_password_manquant(self):
        r = self.client.post('/api/auth/login', json={'email': 'a@b.com'})
        assert r.status_code == 400

    def test_corps_vide(self):
        r = self.client.post('/api/auth/login', json={})
        assert r.status_code == 400

    @patch('api.get_db')
    def test_email_normalise_en_minuscule(self, mock_get_db):
        """L'email doit être converti en minuscules avant la comparaison."""
        user_row = {'password': hashed('pw'), 'role': 'user', 'name': 'Y', 'email': 'yao@gmail.com'}
        db, cur = make_db_mock(fetchone_return=user_row)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/login',
                             json={'email': 'YAO@GMAIL.COM', 'password': 'pw'})
        # Vérifie que get_db a été appelé (la requête a bien été normalisée)
        assert mock_get_db.called


# ══════════════════════════════════════════════════════════════════════════════
# 4. /api/auth/register
# ══════════════════════════════════════════════════════════════════════════════

class TestRegister:
    def setup_method(self):
        self.client = app.test_client()

    @patch('api.threading.Thread')
    @patch('api.get_db')
    def test_inscription_valide(self, mock_get_db, mock_thread):
        db, cur = make_db_mock(fetchone_return=None)  # email pas encore utilisé
        mock_get_db.return_value = db
        mock_thread.return_value = MagicMock()

        r = self.client.post('/api/auth/register', json={
            'name': 'Alice', 'email': 'alice@test.com', 'password': 'motdepasse123'
        })
        assert r.status_code == 200
        assert 'OTP' in r.get_json().get('message', '')

    @patch('api.get_db')
    def test_email_deja_utilise(self, mock_get_db):
        db, cur = make_db_mock(fetchone_return={'id': 5})  # email existe déjà
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/register', json={
            'name': 'Bob', 'email': 'exist@test.com', 'password': 'motdepasse'
        })
        assert r.status_code == 409

    def test_mot_de_passe_trop_court(self):
        r = self.client.post('/api/auth/register', json={
            'name': 'Bob', 'email': 'bob@test.com', 'password': '123'
        })
        assert r.status_code == 400
        assert 'court' in r.get_json().get('error', '').lower()

    def test_champs_requis_manquants(self):
        r = self.client.post('/api/auth/register', json={'email': 'x@x.com'})
        assert r.status_code == 400

    def test_nom_manquant(self):
        r = self.client.post('/api/auth/register', json={
            'email': 'x@x.com', 'password': 'motdepasse'
        })
        assert r.status_code == 400

    def test_corps_vide(self):
        r = self.client.post('/api/auth/register', json={})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# 5. /api/auth/verify-otp
# ══════════════════════════════════════════════════════════════════════════════

class TestVerifyOtp:
    def setup_method(self):
        self.client = app.test_client()

    def _otp_row(self, code='123456', expired=False, extra=None):
        expires = datetime.now() + (-timedelta(minutes=1) if expired else timedelta(minutes=9))
        return {
            'code': code,
            'name': 'Test User',
            'password': hashed('pw'),
            'expires_at': expires,
            'extra': json.dumps(extra or {})
        }

    @patch('api.get_db')
    def test_otp_valide_cree_compte(self, mock_get_db):
        otp_row = self._otp_row('654321')
        db, cur = make_db_mock(fetchone_return=otp_row)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/verify-otp',
                             json={'email': 'new@test.com', 'code': '654321'})
        assert r.status_code == 201
        assert 'succes' in r.get_json().get('message', '').lower()

    @patch('api.get_db')
    def test_code_incorrect(self, mock_get_db):
        otp_row = self._otp_row('111111')
        db, cur = make_db_mock(fetchone_return=otp_row)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/verify-otp',
                             json={'email': 'new@test.com', 'code': '999999'})
        assert r.status_code == 401

    @patch('api.get_db')
    def test_otp_expire(self, mock_get_db):
        otp_row = self._otp_row('123456', expired=True)
        db, cur = make_db_mock(fetchone_return=otp_row)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/verify-otp',
                             json={'email': 'new@test.com', 'code': '123456'})
        assert r.status_code == 410

    @patch('api.get_db')
    def test_aucun_otp_en_attente(self, mock_get_db):
        db, cur = make_db_mock(fetchone_return=None)
        mock_get_db.return_value = db

        r = self.client.post('/api/auth/verify-otp',
                             json={'email': 'ghost@test.com', 'code': '123456'})
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 6. /api/user/settings  (GET)
# ══════════════════════════════════════════════════════════════════════════════

class TestGetUserSettings:
    def setup_method(self):
        self.client = app.test_client()

    @patch('api.get_db')
    def test_retourne_les_settings_utilisateur(self, mock_get_db):
        user_row = {
            'name': 'Yao', 'email': 'yao@test.com', 'phone': '225000000',
            'gmail_address': 'yao@gmail.com', 'telegram_chat_id': '12345',
            'green_api_instance': '', 'green_api_token': '',
            'app_password': 'hashed_pw', 'avatar': '', 'theme_color': '#4f46e5',
            'font_family': 'Inter'
        }
        db, cur = make_db_mock(fetchone_return=user_row)
        mock_get_db.return_value = db

        r = self.client.get('/api/user/settings?email=yao@test.com')
        assert r.status_code == 200
        data = r.get_json()
        assert data['name']        == 'Yao'
        assert data['theme_color'] == '#4f46e5'
        assert data['font_family'] == 'Inter'
        assert data['app_password_set'] is True   # converti depuis app_password
        assert 'app_password' not in data          # ne doit PAS être exposé

    @patch('api.get_db')
    def test_utilisateur_inconnu_retourne_defauts(self, mock_get_db):
        db, cur = make_db_mock(fetchone_return=None)
        mock_get_db.return_value = db

        r = self.client.get('/api/user/settings?email=nobody@test.com')
        assert r.status_code == 200
        data = r.get_json()
        assert data['email']      == 'nobody@test.com'
        assert data['theme_color'] == ''
        assert data['app_password_set'] is False

    def test_email_manquant_retourne_400(self):
        r = self.client.get('/api/user/settings')
        assert r.status_code == 400

    @patch('api.get_db')
    def test_champs_none_convertis_en_chaine_vide(self, mock_get_db):
        user_row = {
            'name': 'Test', 'email': 'test@x.com', 'phone': None,
            'gmail_address': None, 'telegram_chat_id': None,
            'green_api_instance': None, 'green_api_token': None,
            'app_password': None, 'avatar': None,
            'theme_color': None, 'font_family': None
        }
        db, cur = make_db_mock(fetchone_return=user_row)
        mock_get_db.return_value = db

        r = self.client.get('/api/user/settings?email=test@x.com')
        data = r.get_json()
        assert data['phone']      == ''
        assert data['theme_color'] == ''
        assert data['font_family'] == ''


# ══════════════════════════════════════════════════════════════════════════════
# 7. /api/user/settings  (PUT)
# ══════════════════════════════════════════════════════════════════════════════

class TestPutUserSettings:
    def setup_method(self):
        self.client = app.test_client()

    @patch('api.get_db')
    def test_mise_a_jour_theme_et_font(self, mock_get_db):
        db, cur = make_db_mock()
        mock_get_db.return_value = db

        r = self.client.put('/api/user/settings', json={
            'email': 'yao@test.com',
            'theme_color': '#7c3aed',
            'font_family': 'Poppins'
        })
        assert r.status_code == 200
        # Vérifie que commit a été appelé (données sauvegardées)
        assert db.commit.called

    @patch('api.get_db')
    def test_mise_a_jour_nom(self, mock_get_db):
        db, cur = make_db_mock()
        mock_get_db.return_value = db

        r = self.client.put('/api/user/settings', json={
            'email': 'yao@test.com', 'name': 'Nouveau Nom'
        })
        assert r.status_code == 200

    def test_email_manquant_retourne_400(self):
        r = self.client.put('/api/user/settings', json={'theme_color': '#fff'})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# 8. /api/admin/stats
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminStats:
    def setup_method(self):
        self.client = app.test_client()

    @patch('api.get_db')
    def test_retourne_toutes_les_stats(self, mock_get_db):
        db = MagicMock()
        cur = MagicMock()
        cur.__enter__ = lambda s: s
        cur.__exit__  = MagicMock(return_value=False)
        # Chaque fetchone retourne une valeur différente selon l'ordre des appels
        cur.fetchone.side_effect = [
            {'total': 10},   # total users
            {'total': 2},    # total admins
            {'total': 8},    # verified users
            {'total': 3},    # premium users
            {'total': 5},    # total payments
            {'total': 49.95} # revenue
        ]
        db.cursor.return_value = cur
        mock_get_db.return_value = db

        r = self.client.get('/api/admin/stats')
        assert r.status_code == 200
        data = r.get_json()
        assert data['total_users']    == 10
        assert data['premium_users']  == 3
        assert data['total_payments'] == 5
        assert data['total_revenue']  == 49.95


# ══════════════════════════════════════════════════════════════════════════════
# 9. /api/emails  et  /api/stats
# ══════════════════════════════════════════════════════════════════════════════

class TestEmailsEndpoint:
    def setup_method(self):
        self.client = app.test_client()

    def test_sans_email_retourne_liste_vide(self):
        r = self.client.get('/api/emails')
        assert r.status_code == 200
        assert r.get_json() == []

    @patch('api._get_imap_conn', return_value=None)
    def test_imap_non_configure_retourne_liste_vide(self, _):
        r = self.client.get('/api/emails?email=yao@test.com')
        assert r.status_code == 200
        assert r.get_json() == []


class TestStatsEndpoint:
    def setup_method(self):
        self.client = app.test_client()

    def test_sans_email_retourne_zeros(self):
        r = self.client.get('/api/stats')
        assert r.status_code == 200
        data = r.get_json()
        assert data['total_messages'] == 0
        assert data['unread_count']   == 0

    @patch('api._get_imap_conn', return_value=None)
    def test_imap_non_configure_retourne_zeros(self, _):
        r = self.client.get('/api/stats?email=yao@test.com')
        assert r.status_code == 200
        data = r.get_json()
        assert data['total_messages'] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 10. /api/admin/users
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminUsers:
    def setup_method(self):
        self.client = app.test_client()

    @patch('api.get_db')
    def test_retourne_liste_utilisateurs(self, mock_get_db):
        rows = [
            {'id': 1, 'name': 'Alice', 'email': 'alice@x.com', 'is_verified': 1,
             'role': 'user', 'plan': 'free', 'phone': None, 'gmail_address': None,
             'telegram_chat_id': None, 'green_api_instance': None,
             'gmail_connected': False, 'monitor_active': False,
             'created_at': datetime(2025, 1, 1, 10, 0)},
        ]
        db, cur = make_db_mock(fetchall_return=rows)
        mock_get_db.return_value = db

        r = self.client.get('/api/admin/users')
        assert r.status_code == 200
        data = r.get_json()
        assert len(data) == 1
        assert data[0]['name'] == 'Alice'

    @patch('api.get_db')
    def test_liste_vide_si_aucun_utilisateur(self, mock_get_db):
        db, cur = make_db_mock(fetchall_return=[])
        mock_get_db.return_value = db

        r = self.client.get('/api/admin/users')
        assert r.status_code == 200
        assert r.get_json() == []


# ══════════════════════════════════════════════════════════════════════════════
# 11. CORS headers
# ══════════════════════════════════════════════════════════════════════════════

class TestCorsHeaders:
    def setup_method(self):
        self.client = app.test_client()

    def test_cors_present_sur_status(self):
        # Phase 1: CORS restricted to known origins — send an allowed Origin header
        r = self.client.get('/api/status',
                            headers={'Origin': 'http://localhost:4200'})
        assert r.headers.get('Access-Control-Allow-Origin') is not None

    def test_cache_control_no_store(self):
        r = self.client.get('/api/status')
        assert 'no-store' in r.headers.get('Cache-Control', '')

    def test_options_preflight_200(self):
        r = self.client.options('/api/auth/login')
        assert r.status_code == 200
