# -*- coding: utf-8 -*-
"""
קובץ תשתיות קריפטוגרפיות - crypto_utils.py
קובץ זה מכיל פונקציות עזר להצפנה סימטרית (AES), הצפנה א-סימטרית (RSA),
גיבוב (Hashing) וחתימות דיגיטליות באמצעות ספריית cryptography של Python.
הקוד כתוב בצורה מודולרית ונקייה עם הערות מפורטות בעברית כדי לסייע בהבנה ומענה בבוחן.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1, OAEP

# ==========================================
# 1. הצפנה סימטרית (AES - Advanced Encryption Standard)
# ==========================================

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    הצפנת נתונים באמצעות AES במצב CBC (Cipher Block Chaining).
    פונקציה זו תומכת במפתחות בגודל 128 ביט (16 בתים) ו-256 ביט (32 בתים).
    
    פרמטרים:
    plaintext (bytes): המידע הגולמי (בבתים) שיש להצפין.
    key (bytes): מפתח ההצפנה. חייב להיות באורך של 16 או 32 בתים בדיוק.
    
    החזר:
    bytes: ה-IV (וקטור האתחול) בגודל 16 בתים משורשר עם הטקסט המוצפן.
    """
    # בדיקת אורך המפתח לקביעת רמת ההצפנה (128 או 256 ביט)
    if len(key) not in (16, 32):
        raise ValueError("אורך מפתח AES חייב להיות 16 בתים (128 ביט) או 32 בתים (256 ביט) בלבד!")

    # יצירת IV (Initialization Vector) אקראי בגודל 16 בתים (אורך בלוק של AES)
    # ה-IV הכרחי במצב CBC כדי להבטיח שהצפנה של אותו טקסט פעמיים תניב תוצאה שונה
    iv = os.urandom(16)
    
    # ריפוד המידע (Padding) לפי תקן PKCS7
    # מאחר ש-AES עובד על בלוקים קבועים של 128 ביט (16 בתים), עלינו להשלים את המידע לאורך שהוא כפולה של 16
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # יצירת מנוע ההצפנה של AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # ביצוע ההצפנה בפועל
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # החזרת ה-IV יחד עם הטקסט המוצפן. הלקוח יצטרך את אותו ה-IV בדיוק כדי לפענח
    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    פענוח נתונים שהוצפנו ב-AES-CBC.
    
    פרמטרים:
    ciphertext (bytes): ה-IV (16 בתים ראשונים) משורשר עם המידע המוצפן.
    key (bytes): מפתח הפענוח (חייב להתאים למפתח ההצפנה - 16 או 32 בתים).
    
    החזר:
    bytes: המידע המקורי (הטקסט הנקי) לאחר פענוח והסרת הריפוד.
    """
    if len(key) not in (16, 32):
        raise ValueError("אורך מפתח AES חייב להיות 16 בתים (128 ביט) או 32 בתים (256 ביט) בלבד!")

    # חילוץ ה-IV מתוך 16 הבתים הראשונים של המידע המוצפן
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    # יצירת מנוע הפענוח של AES-CBC עם אותו מפתח ואותו IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # פענוח המידע המוצפן (התוצאה עדיין מרופדת)
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    # הסרת הריפוד (Unpadding) לקבלת המידע המקורי
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext


# ==========================================
# 2. הצפנה א-סימטרית (RSA)
# ==========================================

def generate_rsa_keys() -> tuple[bytes, bytes]:
    """
    יצירת זוג מפתחות RSA (מפתח פרטי ומפתח ציבורי) בגודל 2048 ביט.
    
    החזר:
    tuple: (private_key_pem, public_key_pem) כתווים/בתים מיוצאים בתקן PEM.
    """
    # יצירת מפתח פרטי חדש עם מעריך ציבורי סטנדרטי (65537)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # שמירה וייצוא של המפתח הפרטי בפורמט PEM (ללא סיסמה להצפנת הקובץ עצמו, לצורך פשטות)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # חילוץ המפתח הציבורי מתוך המפתח הפרטי וייצוא שלו בפורמט PEM
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


def rsa_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """
    הצפנת מידע באמצעות המפתח הציבורי של הנמען (RSA).
    בפרויקט זה נעשה שימוש בשיטה זו כדי להצפין את מפתח ה-AES במהלך ה-Handshake.
    
    פרמטרים:
    plaintext (bytes): המידע להצפנה (למשל מפתח AES).
    public_key_pem (bytes): המפתח הציבורי בפורמט PEM.
    
    החזר:
    bytes: המידע המוצפן.
    """
    # טעינת המפתח הציבורי מפורמט PEM לאובייקט מפתח ציבורי
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    # ביצוע ההצפנה באמצעות ריפוד OAEP (Optimal Asymmetric Encryption Padding) המאובטח
    # שימוש ב-SHA-256 כפונקציית הגיבוב הפנימית של הריפוד
    ciphertext = public_key.encrypt(
        plaintext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """
    פענוח מידע שהוצפן ב-RSA באמצעות המפתח הפרטי.
    
    פרמטרים:
    ciphertext (bytes): המידע המוצפן.
    private_key_pem (bytes): המפתח הפרטי בפורמט PEM.
    
    החזר:
    bytes: המידע המפוענח המקורי.
    """
    # טעינת המפתח הפרטי מפורמט PEM לאובייקט מפתח פרטי
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # ביצוע הפענוח עם אותם פרמטרי ריפוד OAEP ו-SHA-256 ששימשו להצפנה
    plaintext = private_key.decrypt(
        ciphertext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# ==========================================
# 3. פונקציות גיבוב וחתימה (Hash & Signatures)
# ==========================================

def hash_data(data: bytes, algorithm: str = 'SHA-256') -> bytes:
    """
    חישוב ערך גיבוב (Hash) של נתונים.
    חוסם שימוש ב-SHA-1 וזורק שגיאה מתאימה כדי להבטיח שימוש באלגוריתמים בטוחים בלבד.
    
    פרמטרים:
    data (bytes): המידע לגיבוב.
    algorithm (str): שם אלגוריתם הגיבוב. ברירת מחדל היא SHA-256.
    
    החזר:
    bytes: ערך הגיבוב המחושב.
    """
    # חסימה מפורשת של SHA-1 למניעת חולשות אבטחה ידועות (התקפות התנגשות)
    if algorithm.upper() in ('SHA-1', 'SHA1'):
        raise ValueError("אבטחה נמוכה! השימוש ב-SHA-1 חסום מטעמי אבטחה. נא להשתמש ב-SHA-256 ומעלה.")
        
    if algorithm.upper() != 'SHA-256':
        raise ValueError(f"אלגוריתם {algorithm} אינו נתמך במערכת זו. נא להשתמש ב-SHA-256.")

    # חישוב ה-Hash באמצעות SHA-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def rsa_sign(data: bytes, private_key_pem: bytes, algorithm: str = 'SHA-256') -> bytes:
    """
    יצירת חתימה דיגיטלית על מידע באמצעות המפתח הפרטי של השולח (למשל ה-CA).
    הפונקציה חוסמת שימוש ב-SHA-1 ומשתמשת בריפוד PSS המודרני.
    
    פרמטרים:
    data (bytes): המידע שעליו חותמים.
    private_key_pem (bytes): המפתח הפרטי לחתימה בפורמט PEM.
    algorithm (str): אלגוריתם הגיבוב שבו נשתמש לחתימה.
    
    החזר:
    bytes: החתימה הדיגיטלית.
    """
    # חסימת SHA-1 כפי שנדרש בדרישות הפרויקט
    if algorithm.upper() in ('SHA-1', 'SHA1'):
        raise ValueError("אבטחה נמוכה! השימוש ב-SHA-1 חסום ליצירת חתימות דיגיטליות.")

    if algorithm.upper() != 'SHA-256':
        raise ValueError(f"אלגוריתם {algorithm} אינו נתמך לחתימה. נא להשתמש ב-SHA-256.")

    # טעינת המפתח הפרטי
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # חתימה על המידע באמצעות ריפוד PSS (Probabilistic Signature Scheme) המאובטח ביותר ל-RSA
    signature = private_key.sign(
        data,
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_verify(data: bytes, signature: bytes, public_key_pem: bytes, algorithm: str = 'SHA-256') -> bool:
    """
    אימות חתימה דיגיטלית באמצעות המפתח הציבורי של החותם.
    
    פרמטרים:
    data (bytes): המידע המקורי עליו בוצעה החתימה.
    signature (bytes): החתימה שברצוננו לאמת.
    public_key_pem (bytes): המפתח הציבורי של החותם (למשל ה-CA) בפורמט PEM.
    algorithm (str): אלגוריתם הגיבוב שבו השתמשו לחתימה.
    
    החזר:
    bool: True אם החתימה תקפה ותואמת למידע, אחרת זורק שגיאה (InvalidSignature) או מחזיר False.
    """
    if algorithm.upper() in ('SHA-1', 'SHA1'):
        raise ValueError("אבטחה נמוכה! אימות באמצעות SHA-1 חסום.")

    if algorithm.upper() != 'SHA-256':
        raise ValueError(f"אלגוריתם {algorithm} אינו נתמך לאימות. נא להשתמש ב-SHA-256.")

    # טעינת המפתח הציבורי של החותם
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    try:
        # ביצוע אימות החתימה הדיגיטלית עם אותו ריפוד PSS ופונקציית גיבוב SHA-256
        public_key.verify(
            signature,
            data,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # אם האימות נכשל מכל סיבה שהיא
        return False
