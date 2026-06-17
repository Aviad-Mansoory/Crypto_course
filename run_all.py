# -*- coding: utf-8 -*-
"""
סקריפט הרצה אוטומטי - run_all.py
מפעיל את כל רכיבי המערכת במקביל:
1. אתחול ה-CA (יצירת מפתחות ca_private.pem ו-ca_public.pem במידת הצורך).
2. הפעלת השרת (server.py) בחלון טרמינל נפרד (Console) שיציג את הסברי הלוגים.
3. הפעלת הלקוח הגרפי (client_gui.py).
הקוד כתוב בעברית ומתאים להפעלה במערכת הפעלה Windows.
"""

import subprocess
import time
import sys
import os

def run_everything():
    print("==================================================")
    print("  מערכת הרצה אוטומטית - פרויקט תקשורת היברידית")
    print("==================================================")
    
    # נתיב תיקיית העבודה הנוכחית
    cwd = os.path.dirname(os.path.abspath(__file__))
    
    # שלב א': אתחול מפתחות ה-CA
    print("\n[+] שלב א': מאתחל את מפתחות ה-CA (ca_manager.py)...")
    # הרצת ca_manager באופן סינכרוני כדי לוודא שיש מפתחות CA לפני שהשרת והלקוח עולים
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    
    # הרצה בעזרת מפרש הפייתון הנוכחי
    subprocess.run([sys.executable, "ca_manager.py"], cwd=cwd, env=env)
    
    # שלב ב': הפעלת השרת בחלון קונסול חדש
    print("\n[+] שלב ב': מפעיל את השרת (server.py) בחלון מסוף (Console) נפרד...")
    if os.name == 'nt':
        # פקודה ייעודית לווינדוס: פותחת חלון CMD חדש, מגדירה קידוד UTF-8 ומריצה את השרת
        # הארגומנט /k ב-cmd דואג שהחלון יישאר פתוח גם אם השרת נופל/נעצר
        cmd_command = f'start cmd /k "set PYTHONIOENCODING=utf-8 && title Cryptography Secure Server && "{sys.executable}" server.py"'
        subprocess.Popen(cmd_command, shell=True, cwd=cwd)
    else:
        # תמיכה בסיסית למערכות יוניקס/לינוקס/מק (מריץ ברקע ללא חלון נפרד)
        subprocess.Popen([sys.executable, "server.py"], cwd=cwd, env=env)
        
    # המתנה קלה כדי לאפשר לשרת לעלות, לייצר את המפתחות והתעודה שלו, ולהתחיל להאזין לפורט 8080
    print("[+] ממתין 1.5 שניות לעליית השרת...")
    time.sleep(1.5)
    
    # שלב ג': הפעלת הלקוח עם הממשק הגרפי (GUI)
    print("\n[+] שלב ג': מפעיל את ממשק הלקוח (client_gui.py)...")
    subprocess.run([sys.executable, "client_gui.py"], cwd=cwd, env=env)
    
    print("\n==================================================")
    print("  הרצת המערכת הסתיימה.")
    print("==================================================")

if __name__ == "__main__":
    run_everything()
