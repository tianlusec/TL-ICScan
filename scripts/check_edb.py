import sqlite3
import os

db_path = "tianlu_intel_v2.db"
if not os.path.exists(db_path):
    print("DB not found")
else:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM cve_records WHERE sources LIKE '%exploit_db%'")
    count_underscore = cursor.fetchone()[0]
    print(f"Exploit_DB (underscore) source count: {count_underscore}")

    cursor.execute("SELECT count(*) FROM cve_records WHERE sources LIKE '%exploit-db%'")
    count = cursor.fetchone()[0]
    print(f"Exploit-DB (dash) source count: {count}")

    cursor.execute("SELECT count(*) FROM cve_records WHERE exploit_exists=1")
    exploit_count = cursor.fetchone()[0]
    print(f"Exploit exists count: {exploit_count}")
    
    cursor.execute("SELECT count(*) FROM cve_records")
    total = cursor.fetchone()[0]
    print(f"Total count: {total}")
    conn.close()
