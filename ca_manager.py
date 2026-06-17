# -*- coding: utf-8 -*-
"""
ניהול רשות אישורים פיקטיבית - ca_manager.py
קובץ זה מדמה רשות אישורים (Certificate Authority - CA).
ה-CA מייצר זוג מפתחות משלו, חותם על המפתח הציבורי של השרת ומייצר תעודת אישור דיגיטלית בפורמט JSON,
ומאפשר ללקוח לאמת את התעודה באמצעות המפתח הציבורי של ה-CA.
הקוד כתוב בצורה מודולרית ונקייה עם הערות מפורטות בעברית.
"""

import os
import json
from crypto_utils import generate_rsa_keys, rsa_sign, rsa_verify

# נתיבים לקבצי המפתחות של ה-CA
CA_PRIVATE_KEY_PATH = "ca_private.pem"
CA_PUBLIC_KEY_PATH = "ca_public.pem"
ISSUER_NAME = "FakeRootCA"

def initialize_ca():
    """
    אתחול ה-CA: יצירת מפתח פרטי וציבורי עבור ה-CA ושמירתם בקבצים מקומיים במידה והם לא קיימים.
    הלקוח יחזיק מראש את המפתח הציבורי של ה-CA (ca_public.pem) כדי לבדוק תעודות של שרתים.
    """
    if not os.path.exists(CA_PRIVATE_KEY_PATH) or not os.path.exists(CA_PUBLIC_KEY_PATH):
        print("[CA] מפתחות ה-CA אינם קיימים. מייצר מפתחות חדשים...")
        private_pem, public_pem = generate_rsa_keys()
        
        # שמירת המפתח הפרטי של ה-CA (חייב להישאר סודי ומאובטח)
        with open(CA_PRIVATE_KEY_PATH, "wb") as priv_file:
            priv_file.write(private_pem)
            
        # שמירת המפתח הציבורי של ה-CA (מופץ לכל הלקוחות מראש)
        with open(CA_PUBLIC_KEY_PATH, "wb") as pub_file:
            pub_file.write(public_pem)
            
        print(f"[CA] מפתחות ה-CA נוצרו בהצלחה ונשמרו ב-{CA_PRIVATE_KEY_PATH} וב-{CA_PUBLIC_KEY_PATH}")
    else:
        print("[CA] מפתחות ה-CA כבר קיימים ומטענים מן הדיסק.")


def get_ca_private_key() -> bytes:
    """קריאת המפתח הפרטי של ה-CA מהקובץ לצורך חתימה על תעודות."""
    with open(CA_PRIVATE_KEY_PATH, "rb") as priv_file:
        return priv_file.read()


def get_ca_public_key() -> bytes:
    """קריאת המפתח הציבורי של ה-CA מהקובץ לצורך אימות תעודות."""
    with open(CA_PUBLIC_KEY_PATH, "rb") as pub_file:
        return pub_file.read()


def create_server_certificate(server_name: str, server_public_key_pem: bytes) -> dict:
    """
    פונקציה המקבלת את פרטי השרת (שם ומפתח ציבורי) ובונה תעודה דיגיטלית חתומה במבנה JSON.
    החתימה תיווצר על ידי ביצוע Hash (SHA-256) על המידע ולאחר מכן חתימה עליו עם המפתח הפרטי של ה-CA.
    
    פרמטרים:
    server_name (str): שם השרת שלו מנפיקים את התעודה (למשל localhost או MyServer).
    server_public_key_pem (bytes): המפתח הציבורי של השרת בפורמט PEM.
    
    החזר:
    dict: מילון המייצג את התעודה הדיגיטלית עם החתימה של ה-CA.
    """
    # המרת המפתח הציבורי למחרוזת טקסט רגילה כדי שניתן יהיה לשמור ב-JSON בקלות
    pub_key_str = server_public_key_pem.decode('utf-8') if isinstance(server_public_key_pem, bytes) else server_public_key_pem
    
    # בניית גוף התעודה ללא החתימה
    cert_data = {
        "server_name": server_name,
        "public_key": pub_key_str,
        "issuer_name": ISSUER_NAME
    }
    
    # סריאליזציה (Serialization) - הפיכת מילון הנתונים למחרוזת JSON ממוינת
    # המיון חשוב מאוד (sort_keys=True) כדי להבטיח שסדר המפתחות תמיד יהיה זהה,
    # אחרת תוספת של רווח או שינוי סדר המפתחות תפגע בחתימה.
    serialized_data = json.dumps(cert_data, sort_keys=True).encode('utf-8')
    
    # יצירת מפתח ה-CA במידה ועדיין לא נוצר
    initialize_ca()
    ca_priv_key = get_ca_private_key()
    
    # חתימה על גוף התעודה הממוין באמצעות המפתח הפרטי של ה-CA ו-SHA-256
    signature = rsa_sign(serialized_data, ca_priv_key, algorithm='SHA-256')
    
    # הוספת החתימה בגירסה מיוצגת בהקסדצימלי (Hex-encoded) למילון התעודה
    cert_data["signature"] = signature.hex()
    
    return cert_data


def verify_certificate(cert: dict, ca_public_key_pem: bytes) -> bool:
    """
    פונקציה לאימות תעודה דיגיטלית של שרת מול המפתח הציבורי של ה-CA.
    
    פרמטרים:
    cert (dict): מילון התעודה (כולל server_name, public_key, issuer_name, ו-signature).
    ca_public_key_pem (bytes): המפתח הציבורי של ה-CA.
    
    החזר:
    bool: True אם התעודה תקינה ולא שונתה, False אחרת.
    """
    # בדיקה שכל השדות הנדרשים קיימים בתעודה
    required_fields = ["server_name", "public_key", "issuer_name", "signature"]
    if not all(field in cert for field in required_fields):
        print("[CA Verification] שגיאה: תעודת השרת חסרה שדות הכרחיים.")
        return False
        
    # שליפת החתימה והמרתה בחזרה מיוצוג הקסדצימלי לבייטים
    signature_hex = cert["signature"]
    signature_bytes = bytes.fromhex(signature_hex)
    
    # יצירת עותק של התעודה ללא שדה החתימה כדי לבדוק את נכונות התוכן
    cert_copy = cert.copy()
    del cert_copy["signature"]
    
    # סריאליזציה של גוף התעודה המקורי באותו פורמט בדיוק
    serialized_data = json.dumps(cert_copy, sort_keys=True).encode('utf-8')
    
    # אימות החתימה הדיגיטלית מול המפתח הציבורי של ה-CA
    is_valid = rsa_verify(serialized_data, signature_bytes, ca_public_key_pem, algorithm='SHA-256')
    
    return is_valid


# הרצה ישירה של הסקריפט ליצירת המפתחות ובדיקה עצמית
if __name__ == "__main__":
    print("--- אתחול ובדיקת מערכת רשות האישורים (Fake CA) ---")
    initialize_ca()
    
    # הדגמה של יצירה ואימות תעודה
    print("\n--- בדיקת מנגנון תעודות: סמל שרת לדוגמה ---")
    # יצירת מפתח שרת לדוגמה
    _, test_server_pub_pem = generate_rsa_keys()
    
    # יצירת התעודה עבור השרת לדוגמה
    cert = create_server_certificate("LocalServerTest", test_server_pub_pem)
    print("התעודה שנוצרה בפורמט JSON:")
    print(json.dumps(cert, indent=4, ensure_ascii=False))
    
    # אימות התעודה
    ca_pub = get_ca_public_key()
    is_ok = verify_certificate(cert, ca_pub)
    print(f"\nהאם התעודה תקינה ומאומתת? {is_ok}")
    
    # ניסיון זיוף תעודה (שינוי שם השרת לאחר החתימה)
    print("\n--- בדיקת זיוף תעודה (שינוי שם השרת ללא שינוי החתימה) ---")
    cert["server_name"] = "HackerServer"
    is_ok_fake = verify_certificate(cert, ca_pub)
    print(f"האם התעודה המזויפת עברה אימות? {is_ok_fake} (מצוין, החתימה מונעת שינויים!)")
