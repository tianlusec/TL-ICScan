import sqlite3
import os

db_path = 'tianlu_intel_v2.db'
if not os.path.exists(db_path):
    print("Database not found!")
else:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(1) FROM cve_records WHERE sources LIKE '%github_poc%'")
        count = cursor.fetchone()[0]
        print(f"GitHub PoC Records: {count}")
        
        if count == 0:
            print("No GitHub PoC records found. Checking total records...")
            cursor.execute("SELECT COUNT(1) FROM cve_records")
            total = cursor.fetchone()[0]
            print(f"Total Records: {total}")
            
        conn.close()
    except Exception as e:
        print(f"Error: {e}")
