"""
Locust performance tests — MailNotifier backend
Target: https://backend-mail-1.onrender.com

Run locally:
  locust -f locustfile.py --host https://backend-mail-1.onrender.com

Run headless (CI):
  locust -f locustfile.py --host https://backend-mail-1.onrender.com \
         --headless -u 20 -r 5 --run-time 60s
"""

import json
import random
import string
from locust import HttpUser, TaskSet, task, between, events


# ── Helpers ────────────────────────────────────────────────────────────────────

def random_email():
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"test_{suffix}@mailnotifier-test.com"


# ⚠️  Crée un compte dédié sur l'app puis mets les credentials ici
TEST_USER_EMAIL    = "testlocust@mailnotifier-test.com"
TEST_USER_PASSWORD = "LocustTest123!"


# ── Scénario 1 : Visiteur anonyme ─────────────────────────────────────────────

class AnonymousUserTasks(TaskSet):
    """Simule un visiteur qui découvre l'app."""

    @task(5)
    def health_check(self):
        with self.client.get("/api/version", name="GET /api/version", catch_response=True) as r:
            if r.status_code == 200 and "version" in r.text:
                r.success()
            else:
                r.failure(f"Unexpected: {r.status_code}")

    @task(4)
    def chatbot_product_question(self):
        payload = {
            "message": "C'est quoi MailNotifier ?",
            "history": []
        }
        with self.client.post("/api/chatbot", json=payload,
                              name="POST /api/chatbot (cold)", catch_response=True) as r:
            if r.status_code == 200 and "response" in r.text:
                r.success()
            else:
                r.failure(f"Chatbot failed: {r.status_code} — {r.text[:120]}")

    @task(3)
    def chatbot_with_history(self):
        payload = {
            "message": "Combien ça coûte ?",
            "history": [
                {"role": "user",  "text": "C'est quoi MailNotifier ?"},
                {"role": "bot",   "text": "MailNotifier surveille ta boîte Gmail…"},
            ]
        }
        with self.client.post("/api/chatbot", json=payload,
                              name="POST /api/chatbot (history)", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"{r.status_code}")

    @task(2)
    def register_attempt(self):
        """
        L'inscription nécessite OTP — on teste juste que l'endpoint répond.
        409 (email pris) et 200 sont tous les deux des succès fonctionnels.
        """
        payload = {
            "email":    random_email(),
            "password": "TestPass123!",
        }
        with self.client.post("/api/auth/register", json=payload,
                              name="POST /api/auth/register", catch_response=True) as r:
            # 200/201 = inscrit, 409 = déjà pris, 422 = validation = tous OK
            if r.status_code in (200, 201, 409, 422):
                r.success()
            else:
                r.failure(f"Register unexpected: {r.status_code} — {r.text[:100]}")

    @task(1)
    def chatbot_offtopic(self):
        payload = {"message": "Qui est Messi ?", "history": []}
        with self.client.post("/api/chatbot", json=payload,
                              name="POST /api/chatbot (off-topic)", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"{r.status_code}")


class AnonymousUser(HttpUser):
    tasks        = [AnonymousUserTasks]
    wait_time    = between(1, 4)
    weight       = 60   # 60 % du trafic


# ── Scénario 2 : Utilisateur authentifié ──────────────────────────────────────

class AuthenticatedUserTasks(TaskSet):
    """Simule un utilisateur connecté qui consulte son dashboard."""

    token = None

    def on_start(self):
        """Login au démarrage, stocke le token."""
        try:
            resp = self.client.post("/api/auth/login", json={
                "email":    TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD,
            }, name="POST /api/auth/login (setup)")
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("token") or data.get("access_token")
            else:
                print(f"[Auth] Login failed ({resp.status_code}) — tasks will run unauthenticated")
        except Exception as e:
            print(f"[Auth] Login error: {e}")

    def _auth_headers(self):
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    @task(6)
    def get_user_settings(self):
        params = {"email": TEST_USER_EMAIL}
        with self.client.get("/api/user/settings", params=params,
                             headers=self._auth_headers(),
                             name="GET /api/user/settings", catch_response=True) as r:
            if r.status_code in (200, 401, 403):
                r.success()
            else:
                r.failure(f"{r.status_code}")

    @task(5)
    def get_stats(self):
        params = {"email": TEST_USER_EMAIL}
        with self.client.get("/api/stats", params=params,
                             headers=self._auth_headers(),
                             name="GET /api/stats", catch_response=True) as r:
            if r.status_code in (200, 401, 403):
                r.success()
            else:
                r.failure(f"{r.status_code}")

    @task(4)
    def get_emails(self):
        params = {"email": TEST_USER_EMAIL}
        with self.client.get("/api/emails", params=params,
                             headers=self._auth_headers(),
                             name="GET /api/emails", catch_response=True) as r:
            if r.status_code in (200, 401, 403, 404):
                r.success()
            else:
                r.failure(f"{r.status_code}")

    @task(2)
    def check_gmail_status(self):
        params = {"email": TEST_USER_EMAIL}
        with self.client.get("/api/gmail/status", params=params,
                             headers=self._auth_headers(),
                             name="GET /api/gmail/status", catch_response=True) as r:
            if r.status_code in (200, 401, 403, 404):
                r.success()
            else:
                r.failure(f"{r.status_code}")

    @task(1)
    def chatbot_dashboard_question(self):
        payload = {"message": "Comment activer les notifications WhatsApp ?", "history": []}
        with self.client.post("/api/chatbot", json=payload,
                              name="POST /api/chatbot (auth user)", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"{r.status_code}")


class AuthenticatedUser(HttpUser):
    tasks     = [AuthenticatedUserTasks]
    wait_time = between(2, 6)
    weight    = 30   # 30 % du trafic


# ── Scénario 3 : Power user (Analyse IA) ──────────────────────────────────────

class PowerUserTasks(TaskSet):
    """Simule un utilisateur qui sollicite l'analyse IA."""

    @task(1)
    def ai_analyze(self):
        params = {"email": TEST_USER_EMAIL}
        with self.client.get("/api/ai/analyze", params=params,
                             name="GET /api/ai/analyze", catch_response=True,
                             timeout=60) as r:
            if r.status_code in (200, 401, 403, 503):
                r.success()
            else:
                r.failure(f"AI analyze: {r.status_code} — {r.text[:100]}")

    @task(3)
    def version_ping(self):
        with self.client.get("/api/version", name="GET /api/version (power)",
                             catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"{r.status_code}")


class PowerUser(HttpUser):
    tasks     = [PowerUserTasks]
    wait_time = between(15, 45)   # espacé car l'IA est lente
    weight    = 10   # 10 % du trafic
