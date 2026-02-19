import mysql.connector

def init_db():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="123456"
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS mule_detection")
        cursor.execute("USE mule_detection")
        
        # Mandatory table for Forensic Analysis
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_accounts (
                account_id VARCHAR(255) PRIMARY KEY,
                suspicion_score FLOAT,
                detected_patterns TEXT,
                ring_id VARCHAR(50),
                discovery_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
        print("✅ MySQL Database Ready.")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")

def save_mule(account_id, score, patterns, ring_id):
    try:
        conn = mysql.connector.connect(host="localhost", user="root", password="yourpassword", database="mule_detection")
        cursor = conn.cursor()
        pattern_str = ",".join(patterns)
        query = """
            INSERT INTO suspicious_accounts (account_id, suspicion_score, detected_patterns, ring_id) 
            VALUES (%s, %s, %s, %s) 
            ON DUPLICATE KEY UPDATE suspicion_score=%s, detected_patterns=%s
        """
        cursor.execute(query, (account_id, score, pattern_str, ring_id, score, pattern_str))
        conn.commit()
        conn.close()
    except:
        pass