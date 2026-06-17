# -*- coding: utf-8 -*-
"""
אפליקציית הלקוח עם GUI - client_gui.py
ממשק משתמש חזותי (GUI) מבוסס Tkinter המציג את תהליך לחיצת היד ההיברידית.
הלקוח מתחבר לשרת, מקבל את התעודה הדיגיטלית שלו, מאמת אותה מול מפתח ה-CA שבידו,
יוצר ומחליף מפתח AES, מעביר פרטי התחברות מוצפנים,
ולבסוף מקבל תמונות מוצפנות, מפענח אותן ומציג אותן על המסך.
הקוד מכיל הערות מפורטות מאוד בעברית.
"""

import socket
import threading
import os
import json
import struct
import io
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk

# ייבוא פונקציות העזר הקריפטוגרפיות
from crypto_utils import aes_encrypt, aes_decrypt, rsa_encrypt
from ca_manager import verify_certificate

# הגדרות חיבור לשרת
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8080
CA_PUBLIC_KEY_PATH = "ca_public.pem"


class CryptoClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("לקוח קריפטוגרפי מאובטח - תקשורת היברידית")
        self.root.geometry("900x700")
        self.root.configure(bg="#1E1E2E")  # רקע כהה ומודרני
        
        # שמירת מצב תקשורת
        self.client_socket = None
        self.aes_key = None
        self.chosen_algorithm = "AES-256"
        self.decrypted_images_tk = []  # מניעת פינוי זכרון (Garbage Collection) של תמונות
        
        # עיצוב רכיבים (Style)
        self.setup_styles()
        
        # בניית ממשק המשתמש
        self.build_ui()
        
        # לוג פתיחה
        self.log("מערכת מוכנה. אנא בחר שיטת הצפנה ולחץ על 'התחבר ובצע Handshake'.", "info")

    def setup_styles(self):
        """הגדרת עיצובים מודרניים לרכיבי ttk"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # עיצוב Frame
        self.style.configure('TFrame', background='#1E1E2E')
        self.style.configure('Card.TFrame', background='#252538', borderwidth=1, relief='solid')
        
        # עיצוב כפתורים
        self.style.configure('Accent.TButton', background='#7287FD', foreground='white', font=('Segoe UI', 10, 'bold'))
        self.style.map('Accent.TButton', background=[('active', '#5C6EFF')])
        
        self.style.configure('Sec.TButton', background='#45475A', foreground='white', font=('Segoe UI', 10))
        self.style.map('Sec.TButton', background=[('active', '#585B70')])
        
        # עיצוב תוויות (Labels)
        self.style.configure('TLabel', background='#1E1E2E', foreground='#CDD6F4', font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', background='#1E1E2E', foreground='#89B4FA', font=('Segoe UI', 14, 'bold'))
        self.style.configure('CardTitle.TLabel', background='#252538', foreground='#A6ADC8', font=('Segoe UI', 11, 'bold'))

    def build_ui(self):
        """בניית מבנה החלונות והרכיבים ב-GUI"""
        # פריסה ראשית: חלוקה לימין ושמאל
        # שמאל: לוגים ותמונות
        # ימין: פאנל שליטה ואימות
        
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- פאנל ימני: בקרה ואימות (רוחב קבוע) ---
        control_panel = ttk.Frame(main_frame, width=300, padding=10)
        control_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        control_panel.pack_propagate(False)
        
        # כותרת פאנל חיבור
        conn_title = ttk.Label(control_panel, text="1. הגדרות חיבור ו-Handshake", style="Title.TLabel")
        conn_title.pack(anchor=tk.E, pady=(0, 10))
        
        # בחירת אלגוריתם סימטרי
        algo_frame = ttk.Frame(control_panel)
        algo_frame.pack(fill=tk.X, pady=5)
        
        self.algo_var = tk.StringVar(value="AES-256")
        self.algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var, values=["AES-256", "AES-128"], state="readonly", width=12)
        self.algo_combo.pack(side=tk.LEFT, padx=5)
        
        algo_label = ttk.Label(algo_frame, text="שיטת AES:")
        algo_label.pack(side=tk.RIGHT, padx=5)
        
        # כפתור התחברות
        self.connect_btn = ttk.Button(control_panel, text="התחבר ובצע Handshake", style="Accent.TButton", command=self.start_handshake_thread)
        self.connect_btn.pack(fill=tk.X, pady=10)
        
        # קו מפריד
        separator = ttk.Separator(control_panel, orient='horizontal')
        separator.pack(fill=tk.X, pady=15)
        
        # כותרת פאנל הזדהות
        auth_title = ttk.Label(control_panel, text="2. הזדהות (Authentication)", style="Title.TLabel")
        auth_title.pack(anchor=tk.E, pady=(0, 10))
        
        # טופס שם משתמש וסיסמה (בתוך כרטיס מעוצב)
        self.login_card = ttk.Frame(control_panel, style="Card.TFrame", padding=10)
        self.login_card.pack(fill=tk.X, pady=5)
        
        # שם משתמש
        user_label = ttk.Label(self.login_card, text="שם משתמש:", style="CardTitle.TLabel")
        user_label.pack(anchor=tk.E, pady=2)
        self.user_entry = ttk.Entry(self.login_card, font=('Segoe UI', 10), justify=tk.RIGHT)
        self.user_entry.pack(fill=tk.X, pady=2)
        self.user_entry.insert(0, "aviad") # שם משתמש ברירת מחדל
        self.user_entry.config(state="disabled") # נעול עד לסיום ה-Handshake
        
        # סיסמה
        pass_label = ttk.Label(self.login_card, text="סיסמה:", style="CardTitle.TLabel")
        pass_label.pack(anchor=tk.E, pady=2)
        self.pass_entry = ttk.Entry(self.login_card, show="*", font=('Segoe UI', 10), justify=tk.RIGHT)
        self.pass_entry.pack(fill=tk.X, pady=2)
        self.pass_entry.insert(0, "123456") # סיסמה ברירת מחדל
        self.pass_entry.config(state="disabled") # נעול עד לסיום ה-Handshake
        
        # כפתור התחברות לשרת
        self.login_btn = ttk.Button(control_panel, text="התחבר לשרת", style="Accent.TButton", command=self.start_login_thread, state="disabled")
        self.login_btn.pack(fill=tk.X, pady=15)
        
        # כפתור ניקוי והתחלה מחדש
        self.reset_btn = ttk.Button(control_panel, text="אתחל חיבור", style="Sec.TButton", command=self.reset_connection)
        self.reset_btn.pack(fill=tk.X, pady=5)
        
        # --- פאנל שמאלי: לוגים והצגת תמונות ---
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # כותרת הלוגים
        log_title = ttk.Label(left_panel, text="יומן אירועים קריפטוגרפי (Real-Time Secure Log)", style="Title.TLabel")
        log_title.pack(anchor=tk.W, pady=(0, 5))
        
        # תיבת טקסט ייעודית ללוגים (מדמה טרמינל צבעוני)
        log_frame = ttk.Frame(left_panel)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, height=12, bg="#11111B", fg="#CDD6F4", insertbackground="white", font=("Consolas", 10))
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        # הגדרת צבעים שונים לסוגי הודעות בלוג
        self.log_text.tag_config("info", foreground="#A6ADC8")       # אפור - הודעות כלליות
        self.log_text.tag_config("crypto", foreground="#89B4FA")     # כחול בהיר - פעולות קריפטוגרפיות
        self.log_text.tag_config("security", foreground="#A6E3A1")   # ירוק - אימותים והצלחות אבטחה
        self.style.configure("Green.TLabel", foreground="#A6E3A1", background='#1E1E2E')
        self.log_text.tag_config("error", foreground="#F38BA8")      # אדום - שגיאות וכשלים
        
        # כותרת פאנל תמונות
        img_title = ttk.Label(left_panel, text="תמונות מפוענחות שנתקבלו מהשרת (Decrypted Content)", style="Title.TLabel")
        img_title.pack(anchor=tk.W, pady=(5, 5))
        
        # אזור להצגת התמונות המפוענחות
        self.image_container = ttk.Frame(left_panel, style="Card.TFrame", padding=10)
        self.image_container.pack(fill=tk.BOTH, expand=True)
        
        # הודעה זמנית בתוך הפאנל של התמונות
        self.img_placeholder = ttk.Label(self.image_container, text="התמונות יוצגו כאן לאחר אימות משתמש מוצלח ב-AES", font=('Segoe UI', 11, 'italic'))
        self.img_placeholder.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    # ==========================================
    # פונקציות עזר של ה-GUI
    # ==========================================

    def log(self, message: str, tag: str = "info"):
        """הדפסת הודעה מפורטת לתיבת הטקסט הצבעונית בצורה בטוחה מול Threads"""
        def append_log():
            self.log_text.config(state="normal")
            prefix = "[*] "
            if tag == "crypto":
                prefix = "[Crypto] "
            elif tag == "security":
                prefix = "[Secure] "
            elif tag == "error":
                prefix = "[Error] "
                
            self.log_text.insert(tk.END, f"{prefix}{message}\n", tag)
            self.log_text.see(tk.END) # גלילה אוטומטית לסוף
            self.log_text.config(state="disabled")
            
        self.root.after(0, append_log)

    def reset_connection(self):
        """איפוס הממשק והשקע לצורך ניסיון חיבור חדש"""
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        self.client_socket = None
        self.aes_key = None
        self.decrypted_images_tk.clear()
        
        # איפוס רכיבי ממשק המשתמש
        self.connect_btn.config(state="normal")
        self.algo_combo.config(state="readonly")
        self.user_entry.config(state="disabled")
        self.pass_entry.config(state="disabled")
        self.login_btn.config(state="disabled")
        
        # ניקוי תמונות
        for widget in self.image_container.winfo_children():
            widget.destroy()
            
        self.img_placeholder = ttk.Label(self.image_container, text="התמונות יוצגו כאן לאחר אימות משתמש מוצלח ב-AES", font=('Segoe UI', 11, 'italic'))
        self.img_placeholder.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        self.log("החיבור אופס. ניתן להתחיל תהליך Handshake מחדש.", "info")

    # ==========================================
    # לוגיקת תקשורת וקריפטוגרפיה (רשת ב-Thread)
    # ==========================================

    def start_handshake_thread(self):
        """הפעלת תהליך ה-Handshake ב-Thread נפרד למניעת קפיאת ה-GUI"""
        self.connect_btn.config(state="disabled")
        self.algo_combo.config(state="disabled")
        self.chosen_algorithm = self.algo_var.get()
        
        threading.Thread(target=self.run_handshake, daemon=True).start()

    def run_handshake(self):
        """ביצוע לחיצת יד היברידית מול השרת"""
        try:
            self.log(f"מתחבר לשרת בכתובת {SERVER_HOST}:{SERVER_PORT}...", "info")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            
            # --- שלב 1: שליחת אלגוריתם הצפנה סימטרי נבחר ---
            self.log(f"שולח בקשת חיבור עם שיטת הצפנה סימטרית מבוקשת: {self.chosen_algorithm}", "crypto")
            hello_msg = json.dumps({"algorithm": self.chosen_algorithm}).encode('utf-8')
            self.send_msg_bytes(hello_msg)
            
            # --- שלב 2: קבלת תעודת השרת מהשרת ---
            self.log("ממתין לקבלת תעודת זהות חתומה מהשרת...", "info")
            cert_data = self.recv_msg_bytes()
            if not cert_data:
                raise ConnectionError("השרת סגר את החיבור ללא שליחת תעודה.")
                
            server_cert = json.loads(cert_data.decode('utf-8'))
            self.log(f"תעודה דיגיטלית התקבלה מהשרת (מנפיק: {server_cert.get('issuer_name')})", "crypto")
            
            # --- שלב 3: אימות התעודה מול מפתח ה-CA הציבורי שברשותנו ---
            if not os.path.exists(CA_PUBLIC_KEY_PATH):
                raise FileNotFoundError(f"מפתח ה-CA הציבורי ({CA_PUBLIC_KEY_PATH}) לא נמצא! אנא הרץ תחילה את ca_manager.py ליצירת תשתיות ה-CA.")
                
            with open(CA_PUBLIC_KEY_PATH, "rb") as ca_pub_file:
                ca_public_key_pem = ca_pub_file.read()
                
            self.log("מבצע אימות חתימת ה-CA על תעודת השרת באמצעות מפתח ה-CA הציבורי...", "crypto")
            is_cert_valid = verify_certificate(server_cert, ca_public_key_pem)
            
            if not is_cert_valid:
                self.log("זהירות! אימות חתימת התעודה נכשל! התעודה אינה בתוקף או שונתה!", "error")
                messagebox.showerror("כשל אבטחה חמור", "אימות תעודת השרת נכשל! החיבור נסגר מטעמי בטיחות (חשד ל-Man-in-the-Middle).")
                self.reset_connection()
                return
                
            self.log("התעודה אומתה בהצלחה! מפתח ה-CA הציבורי אישר את זהות השרת.", "security")
            
            # חילוץ המפתח הציבורי של השרת מתוך התעודה המאומתת
            server_public_key_pem = server_cert["public_key"].encode('utf-8')
            
            # --- שלב 4: הגרלת מפתח AES, הצפנתו ב-RSA ושליחתו לשרת ---
            self.log("מגריל מפתח AES סימטרי אקראי מאובטח...", "crypto")
            # 16 בתים עבור AES-128, ו-32 בתים עבור AES-256
            key_len = 32 if self.chosen_algorithm == "AES-256" else 16
            self.aes_key = os.urandom(key_len)
            
            self.log(f"מפתח AES בגודל {key_len * 8} ביט נוצר באופן אקראי (בזיכרון בלבד).", "crypto")
            self.log("מצפין את מפתח ה-AES באמצעות המפתח הציבורי של השרת (RSA-OAEP)...", "crypto")
            
            encrypted_aes_key = rsa_encrypt(self.aes_key, server_public_key_pem)
            self.log(f"שולח את מפתח ה-AES המוצפן לשרת (גודל מוצפן: {len(encrypted_aes_key)} בתים)...", "info")
            self.send_msg_bytes(encrypted_aes_key)
            
            # סיום מוצלח של ה-Handshake - מעתה והלאה התקשורת תהיה מוצפנת ב-AES!
            self.log("תהליך ה-Handshake הושלם בהצלחה! הערוץ מאובטח ומוצפן מעתה באמצעות AES.", "security")
            
            # הפעלת רכיבי ההזדהות ב-GUI
            self.root.after(0, self.enable_login_fields)
            
        except Exception as e:
            self.log(f"שגיאה בתהליך ה-Handshake: {e}", "error")
            messagebox.showerror("שגיאת חיבור", f"כשל ביצירת ערוץ מאובטח:\n{e}")
            self.reset_connection()

    def enable_login_fields(self):
        """הפעלת כפתור ושדות הטקסט של ההזדהות לאחר סיום ה-Handshake"""
        self.user_entry.config(state="normal")
        self.pass_entry.config(state="normal")
        self.login_btn.config(state="normal")

    def start_login_thread(self):
        """הפעלת תהליך האימות ב-Thread נפרד"""
        self.login_btn.config(state="disabled")
        threading.Thread(target=self.run_login, daemon=True).start()

    def run_login(self):
        """ביצוע תהליך האימות והעברת התמונות בצורה מוצפנת ב-AES"""
        try:
            username = self.user_entry.get()
            password = self.pass_entry.get()
            
            if not username or not password:
                messagebox.showwarning("שדות חסרים", "נא להזין שם משתמש וסיסמה.")
                self.root.after(0, lambda: self.login_btn.config(state="normal"))
                return
                
            # --- שלב 1: הצפנת שם משתמש וסיסמה ב-AES ושליחתם ---
            self.log("מצפין את פרטי ההתחברות באמצעות מפתח ה-AES המשותף...", "crypto")
            creds_data = json.dumps({"username": username, "password": password}).encode('utf-8')
            encrypted_creds = aes_encrypt(creds_data, self.aes_key)
            
            self.log("שולח את פרטי ההתחברות המוצפנים לשרת...", "info")
            self.send_msg_bytes(encrypted_creds)
            
            # --- שלב 2: קבלת תוצאת האימות מהשרת ---
            self.log("ממתין לתשובת השרת (מאובטחת ב-AES)...", "info")
            encrypted_response = self.recv_msg_bytes()
            if not encrypted_response:
                raise ConnectionError("השרת סגר את החיבור ללא החזרת תשובת אימות.")
                
            # פענוח תשובת השרת
            response_bytes = aes_decrypt(encrypted_response, self.aes_key)
            response_json = json.loads(response_bytes.decode('utf-8'))
            
            if response_json.get("status") == "success":
                self.log("אימות המשתמש הצליח! השרת אישר את ההתחברות.", "security")
                
                # --- שלב 3: קבלת התמונות המוצפנות ופענוחן ---
                self.log("ממתין לקבלת הודעת מידע על תמונות...", "info")
                encrypted_info = self.recv_msg_bytes()
                info_bytes = aes_decrypt(encrypted_info, self.aes_key)
                image_info = json.loads(info_bytes.decode('utf-8'))
                
                image_count = image_info.get("image_count", 0)
                self.log(f"השרת מדווח על {image_count} תמונות שיישלחו כעת בצורה מוצפנת.", "crypto")
                
                # ניקוי מיכל התמונות ב-GUI לקראת הצגת התמונות החדשות
                self.root.after(0, self.clear_image_container)
                
                for i in range(image_count):
                    self.log(f"מקבל תמונה מוצפנת מס' {i+1} מתוך {image_count}...", "info")
                    encrypted_img = self.recv_msg_bytes()
                    if not encrypted_img:
                        raise ConnectionError(f"קבלת תמונה {i+1} נכשלה - החיבור נקטע.")
                        
                    self.log(f"תמונה {i+1} התקבלה (גודל מוצפן: {len(encrypted_img)} בתים). מפענח ב-AES...", "crypto")
                    # פענוח קובץ התמונה (JPEG) באמצעות מפתח ה-AES המשותף
                    img_bytes = aes_decrypt(encrypted_img, self.aes_key)
                    self.log(f"תמונה {i+1} פוענחה בהצלחה ב-AES (גודל מקורי: {len(img_bytes)} בתים).", "security")
                    
                    # הצגת התמונה בממשק המשתמש (עיבוד תמונה ב-Thread הראשי)
                    self.root.after(0, self.display_decrypted_image, img_bytes)
                    
                self.log("העברת כל התמונות הסתיימה ופוענחה בהצלחה!", "security")
                
            else:
                error_msg = response_json.get("message", "שגיאה לא ידועה")
                self.log(f"האימות נכשל: {error_msg}", "error")
                messagebox.showerror("אימות נכשל", f"כשל בהתחברות לשרת:\n{error_msg}")
                self.root.after(0, lambda: self.login_btn.config(state="normal"))
                
        except Exception as e:
            self.log(f"שגיאה בתהליך האימות וקבלת המידע: {e}", "error")
            messagebox.showerror("שגיאה", f"כשל בתהליך התקשורת:\n{e}")
            self.reset_connection()

    def clear_image_container(self):
        """ניקוי רכיבים ממיכל התמונות ב-GUI"""
        self.decrypted_images_tk.clear()
        for widget in self.image_container.winfo_children():
            widget.destroy()

    def display_decrypted_image(self, img_bytes: bytes):
        """הצגת תמונה מפוענחת בממשק המשתמש"""
        try:
            # המרת הבתים המפוענחים לאובייקט תמונה של PIL
            image = Image.open(io.BytesIO(img_bytes))
            
            # שינוי גודל התמונה כך שתתאים להצגה ב-GUI
            image.thumbnail((180, 150))
            
            # המרה לאובייקט שתואם ל-Tkinter
            img_tk = ImageTk.PhotoImage(image)
            self.decrypted_images_tk.append(img_tk) # שמירת התמונה בזכרון
            
            # יצירת מסגרת ותווית להצגת התמונה
            img_frame = ttk.Frame(self.image_container, padding=5, style="TFrame")
            img_frame.pack(side=tk.LEFT, padx=10, fill=tk.BOTH)
            
            img_label = ttk.Label(img_frame, image=img_tk)
            img_label.pack()
            
            # כיתוב קטן מתחת לתמונה המאשר כי התמונה פוענחה ב-AES
            caption_label = ttk.Label(img_frame, text="[מפוענח ב-AES]", style="Green.TLabel", font=('Consolas', 8))
            caption_label.pack(pady=2)
            
        except Exception as e:
            self.log(f"שגיאה בהצגת התמונה המפוענחת: {e}", "error")

    # ==========================================
    # פונקציות תשתית למשלוח וקבלת הודעות עם Header
    # ==========================================

    def send_msg_bytes(self, data: bytes):
        """שליחת הודעה לשרת עם Header של 4 בתים המייצג את אורך ההודעה"""
        if not self.client_socket:
            raise ConnectionError("אין חיבור פעיל לשרת.")
        length_prefix = struct.pack('!I', len(data))
        self.client_socket.sendall(length_prefix + data)

    def recv_msg_bytes(self) -> bytes:
        """קבלת הודעה מהשרת על בסיס Header של 4 בתים המייצג את האורך"""
        if not self.client_socket:
            raise ConnectionError("אין חיבור פעיל לשרת.")
            
        header = self.recv_all_bytes(4)
        if not header:
            return None
            
        msg_len = struct.unpack('!I', header)[0]
        return self.recv_all_bytes(msg_len)

    def recv_all_bytes(self, length: int) -> bytes:
        """פונקציית עזר המבטיחה שנקרא בדיוק את מספר הבתים המבוקש מהשקע"""
        data = b''
        while len(data) < length:
            packet = self.client_socket.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoClientGUI(root)
    
    # הבטחת סגירת ה-Socket במידה והמשתמש סוגר את חלון ה-GUI
    def on_closing():
        if app.client_socket:
            try:
                app.client_socket.close()
            except Exception:
                pass
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
