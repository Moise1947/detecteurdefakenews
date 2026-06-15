import mysql.connector
from mysql.connector import Error

try:
    conn = mysql.connector.connect(
        host="127.0.0.1",
        user="fakenews_app",
        password="root",   # ou ton vrai mot de passe
        database="fakenews_db",
        port=3306
    )

    if conn.is_connected():
        print("✅ Connexion MySQL réussie !")

    conn.close()

except Error as e:
    print("❌ Erreur connexion MySQL :")
    print(e)