#!/usr/bin/env python3
"""
Script de test pour vérifier la connexion et les identifiants dans la base de données
"""
import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
import hashlib

load_dotenv()

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

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def test_connection():
    print("=== TEST DE CONNEXION À LA BASE DE DONNÉES ===")
    
    try:
        db = get_db()
        print("✅ Connexion à la base réussie")
        
        with db.cursor() as cur:
            # Vérifier la structure de la table users
            print("\n=== STRUCTURE DE LA TABLE USERS ===")
            cur.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'users' 
                ORDER BY ordinal_position
            """)
            columns = cur.fetchall()
            for col in columns:
                print(f"- {col['column_name']}: {col['data_type']}")
            
            # Compter les utilisateurs
            print("\n=== UTILISATEURS DANS LA BASE ===")
            cur.execute("SELECT COUNT(*) as count FROM users")
            count = cur.fetchone()
            print(f"Nombre total d'utilisateurs: {count['count']}")
            
            # Lister tous les utilisateurs (masqués pour la sécurité)
            print("\n=== LISTE DES UTILISATEURS ===")
            cur.execute("SELECT id, email, name, is_verified FROM users")
            users = cur.fetchall()
            
            if not users:
                print("❌ Aucun utilisateur trouvé dans la base!")
                return
            
            for user in users:
                status = "✅ Vérifié" if user['is_verified'] else "❌ Non vérifié"
                print(f"ID: {user['id']}, Email: {user['email']}, Nom: {user['name']}, Status: {status}")
            
            # Test de connexion avec identifiants spécifiques
            print("\n=== TEST DE CONNEXION ===")
            test_emails = [
                "yaoyanissekyliane@gmail.com",
                "test@test.com",
                "admin@admin.com"
            ]
            
            for email in test_emails:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                
                if user:
                    print(f"✅ Utilisateur trouvé: {email}")
                    print(f"   - ID: {user['id']}")
                    print(f"   - Nom: {user['name']}")
                    print(f"   - Vérifié: {user['is_verified']}")
                    print(f"   - Hash du mot de passe: {user['password'][:20]}...")
                    
                    # Test avec différents mots de passe courants
                    test_passwords = ["password", "123456", "admin", "test"]
                    for pwd in test_passwords:
                        hashed = hash_password(pwd)
                        if user['password'] == hashed:
                            print(f"   - ✅ Mot de passe trouvé: {pwd}")
                            break
                    else:
                        print(f"   - ❌ Aucun mot de passe simple trouvé")
                else:
                    print(f"❌ Utilisateur non trouvé: {email}")
        
        db.close()
        print("\n✅ Test terminé avec succès")
        
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        print(f"   Type: {type(e)}")
        import traceback
        print(f"   Détails: {traceback.format_exc()}")

if __name__ == "__main__":
    test_connection()
