# -*- coding: utf-8 -*-
"""
אפליקציית השרת - server.py
שרת TCP מאובטח המממש תקשורת מוצפנת בשיטה היברידית (RSA + AES).
השרת מאמת את זהותו באמצעות תעודת אישור החתומה על ידי ה-CA הפיקטיבי,
מפענח את מפתח ה-AES שנשלח מהלקוח, מאמת שם משתמש וסיסמה,
ולאחר מכן משגר תמונות מוצפנות ב-AES בחזרה ללקוח.
הקוד כתוב עם הערות מפורטות בעברית.
"""

import socket
import threading
import os
import json
import struct
import ca_manager
from crypto_utils import rsa_decrypt, aes_encrypt, aes_decrypt, generate_rsa_keys

# הגדרות הרשת של השרת
HOST = '127.0.0.1'  # האזנה מקומית בלבד
PORT = 8080         # פורט התקשרות
SERVER_PRIVATE_KEY_PATH = "server_private.pem"
SERVER_PUBLIC_KEY_PATH = "server_public.pem"
SERVER_CERT_PATH = "server_cert.json"

# מסד נתונים פנימי של משתמשים וסיסמאות לצורך אימות (במציאות סיסמאות היו נשמרות מוצפנות/מגובבות עם מלח)
USER_DATABASE = {
    "aviad": "123456",
    "student": "crypto2026",
    "guest": "password"
}

# תיקיית התמונות שהשרת ישלח ללקוח לאחר חיבור מוצלח
CATS_DIR = "cats"
IMAGE_FILES = ["cat1.jpg", "cat2.jpg", "cat3.jpg"]


# ==========================================
# פונקציות עזר לתקשורת דרך שקעים (Sockets)
# ==========================================

def send_msg(sock: socket.socket, data: bytes):
    """
    שליחת הודעה ללקוח עם קידומת אורך.
    מנגנון זה פותר את בעיית ה-Fragmentation ב-TCP, שכן הוא מודיע לצד השני מראש
    מהו הגודל (בבתים) של ההודעה/תמונה שעומדת להישלח, על ידי שליחת Header של 4 בתים.
    
    struct.pack('!I', len(data)) יוצר ייצוג בינארי של אורך המידע (Integer) בגודל 4 בתים בפורמט Network Byte Order.
    """
    length_prefix = struct.pack('!I', len(data))
    sock.sendall(length_prefix + data)


def recv_msg(sock: socket.socket) -> bytes:
    """
    קבלת הודעה מהלקוח על בסיס קידומת האורך.
    קורא תחילה 4 בתים כדי לפענח את גודל ההודעה המלאה, ולאחר מכן ממתין עד לקבלת כל הבתים.
    """
    # קריאת ה-Header בגודל 4 בתים
    header = recv_all(sock, 4)
    if not header:
        return None
    
    # פיענוח אורך המידע מתוך ה-Header
    msg_len = struct.unpack('!I', header)[0]
    
    # קריאת המידע עצמו באורך המוגדר
    return recv_all(sock, msg_len)


def recv_all(sock: socket.socket, length: int) -> bytes:
    """
    פונקציית עזר המבטיחה שנקרא בדיוק את מספר הבתים המבוקש.
    בפרוטוקול TCP, קריאה רגילה מ-Socket עלולה להחזיר רק חלק מהמידע אם הוא מפוצל,
    לכן יש לרוץ בלולאה עד לאיסוף כל המידע.
    """
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None # החיבור נסגר באופן לא צפוי
        data += packet
    return data


# ==========================================
# אתחול מפתחות השרת והתעודה
# ==========================================

def initialize_server_credentials():
    """
    אתחול מפתחות ה-RSA של השרת ותעודת ה-CA שלו.
    אם אין לשרת מפתחות, מייצר אותם ומבקש מה-CA לחתום עליהם כדי ליצור את התעודה (server_cert.json).
    """
    # 1. יצירת מפתחות RSA לשרת אם אינם קיימים
    if not os.path.exists(SERVER_PRIVATE_KEY_PATH) or not os.path.exists(SERVER_PUBLIC_KEY_PATH):
        print("[Server] מפתחות השרת אינם קיימים. מייצר מפתחות RSA חדשים (2048 ביט)...")
        private_pem, public_pem = generate_rsa_keys()
        
        with open(SERVER_PRIVATE_KEY_PATH, "wb") as priv_file:
            priv_file.write(private_pem)
        with open(SERVER_PUBLIC_KEY_PATH, "wb") as pub_file:
            pub_file.write(public_pem)
            
        print("[Server] מפתחות השרת נוצרו ונשמרו בהצלחה.")
    
    # 2. יצירת תעודת אישור דיגיטלית חתומה על ידי ה-CA
    if not os.path.exists(SERVER_CERT_PATH):
        print("[Server] תעודת השרת אינה קיימת. פונה ל-CA להנפקת תעודה...")
        
        # קריאת המפתח הציבורי של השרת
        with open(SERVER_PUBLIC_KEY_PATH, "rb") as pub_file:
            server_pub_key = pub_file.read()
            
        # יצירת תעודה חתומה באמצעות ה-CA המקומי
        # התעודה מכילה את שם השרת, המפתח הציבורי שלו, שם המנפיק (FakeRootCA) וחתימה של ה-CA
        cert_dict = ca_manager.create_server_certificate("localhost", server_pub_key)
        
        # שמירת התעודה בקובץ JSON
        with open(SERVER_CERT_PATH, "w", encoding="utf-8") as cert_file:
            json.dump(cert_dict, cert_file, indent=4, ensure_ascii=False)
            
        print(f"[Server] תעודת השרת הונפקה ונשמרה ב-{SERVER_CERT_PATH}")
    else:
        print("[Server] תעודת השרת קיימת ונטענת מהדיסק.")


def get_server_private_key() -> bytes:
    """קריאת המפתח הפרטי של השרת מהקובץ לצורך פענוח מפתח ה-AES."""
    with open(SERVER_PRIVATE_KEY_PATH, "rb") as priv_file:
        return priv_file.read()


# ==========================================
# ניהול שיחת לקוח (Client Handler)
# ==========================================

def handle_client(client_socket: socket.socket, client_address: tuple):
    """
    פונקציה המנהלת את הקשר עם לקוח בודד ב-Thread נפרד.
    מממשת את שלבי הפרוטוקול המאובטח (Handshake, Key Exchange, Authentication, Data Transfer).
    """
    print(f"\n==================================================")
    print(f"[Server] חיבור חדש התקבל מכתובת: {client_address}")
    print(f"==================================================")
    
    try:
        # --- שלב 1: קבלת הודעת פתיחה ובקשת התחברות מהלקוח ---
        hello_data = recv_msg(client_socket)
        if not hello_data:
            print(f"[Server] [שגיאה] החיבור נסגר בשלב הפתיחה על ידי {client_address}")
            return
            
        hello_json = json.loads(hello_data.decode('utf-8'))
        chosen_cipher = hello_json.get("algorithm", "AES-256")
        
        print(f"\n[Server] >>> שלב 1: הלקוח יזם חיבור וביקש שיטת הצפנה סימטרית: {chosen_cipher}")
        print(f"         [הסבר]: הלקוח הגדיר באיזו רמת חוזק של AES ברצונו להצפין את תוכן ההודעות בהמשך (128 או 256 ביט).")
        
        # קביעת אורך המפתח בהתאם לבקשת המשתמש
        if chosen_cipher == "AES-256":
            key_len_bytes = 32
        elif chosen_cipher == "AES-128":
            key_len_bytes = 16
        else:
            print(f"[Server] [שגיאה] אלגוריתם לא נתמך: {chosen_cipher}. סוגר חיבור.")
            client_socket.close()
            return
            
        # --- שלב 2: שליחת תעודת השרת החתומה ללקוח ---
        with open(SERVER_CERT_PATH, "r", encoding="utf-8") as cert_file:
            cert_content = cert_file.read()
            
        print(f"\n[Server] >>> שלב 2: שולח ללקוח את תעודת זהות השרת החתומה ({SERVER_CERT_PATH})")
        print(f"         [הסבר]: התעודה מכילה את שם השרת, המפתח הציבורי שלו ואת החתימה הדיגיטלית של ה-CA הפיקטיבי.")
        print(f"                 הלקוח יאמת את החתימה באמצעות מפתח ה-CA הציבורי שברשותו כדי לוודא שזהו אכן השרת האמיתי ולא מתחזה (מניעת Man-in-the-Middle).")
        send_msg(client_socket, cert_content.encode('utf-8'))
        
        # --- שלב 3: קבלת מפתח AES מוצפן ב-RSA ופענוחו ---
        encrypted_aes_key = recv_msg(client_socket)
        if not encrypted_aes_key:
            print("[Server] [שגיאה] כשל בקבלת מפתח ה-AES המוצפן מהלקוח.")
            return
            
        print(f"\n[Server] >>> שלב 3: התקבל מפתח AES מוצפן מהלקוח. מפענח באמצעות המפתח הפרטי RSA של השרת...")
        print(f"         [הסבר]: הלקוח ייצר מפתח AES סימטרי אקראי חדש, והצפין אותו באמצעות המפתח הציבורי של השרת (RSA-OAEP).")
        print(f"                 רק השרת, המחזיק במפתח הפרטי RSA התואם, מסוגל לפענח אותו. זהו מנגנון החלפת מפתחות היברידי (Key Exchange).")
        
        server_private_pem = get_server_private_key()
        aes_key = rsa_decrypt(encrypted_aes_key, server_private_pem)
        
        # וידוא שאורך המפתח מתאים למה שסוכם בשלב הפתיחה
        if len(aes_key) != key_len_bytes:
            raise ValueError(f"אורך מפתח AES שפוענח ({len(aes_key)} בתים) אינו מתאים לאלגוריתם שנבחר ({key_len_bytes} בתים)")
            
        print(f"[Server] [הצלחה] מפתח ה-AES פוענח בהצלחה! נקבע מפתח סודי משותף בגודל {key_len_bytes * 8} ביט.")
        
        # --- שלב 4: אימות שם משתמש וסיסמה (מוצפנים ב-AES) ---
        print(f"\n[Server] >>> שלב 4: ממתין לקבלת פרטי הזדהות (שם משתמש וסיסמה) מהלקוח...")
        encrypted_creds = recv_msg(client_socket)
        if not encrypted_creds:
            print("[Server] [שגיאה] לא התקבלו פרטי הזדהות מהלקוח.")
            return
            
        print(f"[Server] פרטי הזדהות מוצפנים התקבלו. מפענח ב-AES-CBC באמצעות המפתח המשותף...")
        # פענוח פרטי ההזדהות באמצעות מפתח ה-AES המשותף שנקבע
        creds_json_bytes = aes_decrypt(encrypted_creds, aes_key)
        creds = json.loads(creds_json_bytes.decode('utf-8'))
        
        username = creds.get("username")
        password = creds.get("password")
        print(f"[Server] ניסיון התחברות עבור שם משתמש: '{username}'")
        
        # בדיקה האם המשתמש קיים והסיסמה נכונה במסד הנתונים
        auth_success = False
        if username in USER_DATABASE and USER_DATABASE[username] == password:
            auth_success = True
            print(f"[Server] [הצלחה] משתמש '{username}' אומת בהצלחה במסד הנתונים!")
        else:
            print(f"[Server] [כשל] אימות נכשל עבור המשתמש '{username}' - סיסמה שגויה או משתמש לא קיים.")
            
        # --- שלב 5: שליחת תוצאת האימות מוצפנת ב-AES ---
        print(f"\n[Server] >>> שלב 5: שולח את סטטוס האימות חזרה ללקוח (מוצפן ב-AES)...")
        auth_response = {"status": "success" if auth_success else "failure", "message": "התחברת בהצלחה" if auth_success else "שם משתמש או סיסמה שגויים"}
        auth_response_bytes = json.dumps(auth_response).encode('utf-8')
        encrypted_auth_response = aes_encrypt(auth_response_bytes, aes_key)
        
        send_msg(client_socket, encrypted_auth_response)
        
        # --- שלב 6: שליחת תמונות מוצפנות (אם האימות הצליח) ---
        if auth_success:
            print(f"\n[Server] >>> שלב 6: האימות עבר בהצלחה! מתחיל לקרוא ולשלוח תמונות מוצפנות ב-AES...")
            
            # בדיקת קיום התיקייה והתמונות
            if not os.path.exists(CATS_DIR):
                print(f"[Server] [שגיאה] תיקיית '{CATS_DIR}' אינה קיימת. לא ניתן לשלוח תמונות.")
                send_msg(client_socket, aes_encrypt(json.dumps({"image_count": 0}).encode('utf-8'), aes_key))
                return
                
            # שליחת הודעת הכנה עם כמות התמונות
            info_msg = {"image_count": len(IMAGE_FILES)}
            encrypted_info = aes_encrypt(json.dumps(info_msg).encode('utf-8'), aes_key)
            send_msg(client_socket, encrypted_info)
            
            for img_name in IMAGE_FILES:
                img_path = os.path.join(CATS_DIR, img_name)
                if os.path.exists(img_path):
                    print(f"[Server] קורא את התמונה '{img_name}', ומבצע הצפנת AES-CBC סימטרית...")
                    with open(img_path, "rb") as img_file:
                        img_bytes = img_file.read()
                    
                    # הצפנת קובץ התמונה הגולמי (bytes) באמצעות מפתח ה-AES הסימטרי
                    encrypted_img = aes_encrypt(img_bytes, aes_key)
                    
                    # שליחת קובץ התמונה המוצפן דרך השקע
                    print(f"[Server] שולח {len(encrypted_img)} בתים של תמונה מוצפנת (עם 4 בתים Header המציינים את אורך החבילה)...")
                    send_msg(client_socket, encrypted_img)
                else:
                    print(f"[Server] [שגיאה] קובץ התמונה {img_name} לא נמצא בדיסק.")
            
            print("[Server] [הצלחה] כל התמונות המוצפנות נשלחו ללקוח בהצלחה.")
            
    except Exception as e:
        print(f"[Server] [שגיאה חמורה] שגיאה במהלך הטיפול בלקוח: {e}")
    finally:
        # סגירת החיבור עם הלקוח
        client_socket.close()
        print(f"==================================================")
        print(f"[Server] החיבור עם {client_address} נסגר.")
        print(f"==================================================")


# ==========================================
# פונקציית ההרצה הראשית של השרת
# ==========================================

def start_server():
    """הפעלת השרת, האזנה לחיבורים נכנסים ויצירת Thread ייעודי לכל לקוח."""
    # אתחול מפתחות השרת ותעודה חתומה מה-CA
    initialize_server_credentials()
    
    # יצירת Socket מסוג TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # פתרון לבעיית "Address already in use" - מאפשר הרצה מחדש מהירה של השרת
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # שיוך ה-Socket לכתובת ולפורט
        server_socket.bind((HOST, PORT))
        # הגדרת כמות החיבורים הממתינים בתור
        server_socket.listen(5)
        print(f"\n[Server] השרת רץ ומאזין לחיבורים בכתובת {HOST}:{PORT}...")
        
        while True:
            # המתנה לקבלת חיבור חדש
            client_socket, client_address = server_socket.accept()
            
            # יצירת Thread חדש לטיפול בלקוח כדי שהשרת יוכל להמשיך להאזין ללקוחות נוספים במקביל
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            # הגדרה כ-Daemon כדי שה-Thread ייסגר אוטומטית אם התוכנית הראשית של השרת תיסגר
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[Server] השרת נעצר על ידי המשתמש (Ctrl+C).")
    except Exception as e:
        print(f"[Server] שגיאה בהפעלת השרת: {e}")
    finally:
        server_socket.close()
        print("[Server] ה-Socket הראשי של השרת נסגר.")


if __name__ == "__main__":
    start_server()
