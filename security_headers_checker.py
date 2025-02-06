# security_headers_checker.py
import requests
import psycopg2
from psycopg2.extras import Json  # New import
from config import DB_CONFIG
import argparse
import sys
from dotenv import load_dotenv

load_dotenv()

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

def get_db_connection():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except psycopg2.OperationalError as e:
        print(f"Database connection failed: {e}")
        sys.exit(1)

def create_database_and_table():
    try:
        conn = psycopg2.connect(
            dbname="postgres",
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"]
        )
        conn.autocommit = True
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM pg_database WHERE datname = 'security_headers'")
        if not cur.fetchone():
            print("Creating database 'security_headers'...")
            cur.execute("CREATE DATABASE security_headers")

        cur.close()
        conn.close()

        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cur = conn.cursor()

        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'header_checks'
            )
        """)
        if not cur.fetchone()[0]:
            print("Creating table 'header_checks'...")
            cur.execute("""
                CREATE TABLE header_checks (
                    id SERIAL PRIMARY KEY,
                    url VARCHAR(255) NOT NULL,
                    check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    headers_present JSONB,
                    missing_headers JSONB,
                    score INTEGER
                )
            """)

        cur.close()
    except Exception as e:
        print(f"Database setup error: {e}")
        sys.exit(1)
    finally:
        if 'conn' in locals():
            conn.close()

def check_security_headers(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        response = requests.get(url, timeout=10)
        headers = response.headers

        present = {}
        missing = []
        
        for header in REQUIRED_HEADERS:
            if header in headers:
                present[header] = headers[header]
            else:
                missing.append(header)

        score = int((len(present) / len(REQUIRED_HEADERS)) * 100)
        return present, missing, score

    except requests.exceptions.RequestException as e:
        print(f"Error checking {url}: {e}")
        return {}, [], 0

def save_to_db(url, present, missing, score):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO header_checks (url, headers_present, missing_headers, score)
            VALUES (%s, %s, %s, %s)
        """, (url, Json(present), Json(missing), score))
        
        conn.commit()
    except Exception as e:
        print(f"Error saving to database: {e}")
    finally:
        cur.close()
        conn.close()

def main():
    create_database_and_table()
    parser = argparse.ArgumentParser(description="Security Header Checker")
    parser.add_argument("url", help="URL to check (e.g., https://example.com)")
    args = parser.parse_args()

    present, missing, score = check_security_headers(args.url)
    
    print(f"\nSecurity Header Report for {args.url}")
    print(f"Compliance Score: {score}%")
    
    if present:
        print("\nPresent Headers:")
        for header, value in present.items():
            print(f"  {header}: {value[:60]}{'...' if len(value) > 60 else ''}")
    
    if missing:
        print("\nMissing Headers:")
        for header in missing:
            print(f"  - {header}")

    if present or missing:
        save_to_db(args.url, present, missing, score)
        print("\nResults saved to database!")

if __name__ == "__main__":
    main()
