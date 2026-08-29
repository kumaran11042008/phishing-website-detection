import sqlite3
import os
from datetime import datetime


# ============================================================
# DATABASE PATH
# ============================================================
# Local development:
#     database/scan_history.db
#
# Vercel:
#     /tmp/scan_history.db
#
# Vercel's deployed filesystem is read-only, but /tmp is writable.
# ============================================================

if os.environ.get("VERCEL"):
    DATABASE = "/tmp/scan_history.db"
else:
    DATABASE = os.path.join(
        os.path.dirname(__file__),
        "scan_history.db"
    )


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Create and return a SQLite database connection.
    """

    # Make sure the local database directory exists
    if not os.environ.get("VERCEL"):
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    connection = sqlite3.connect(DATABASE)

    return connection


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL,
            risk TEXT,
            risk_score INTEGER,
            scan_time REAL,
            timestamp TEXT
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    url,
    prediction,
    confidence,
    risk,
    risk_score,
    scan_time
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans
        (url, prediction, confidence, risk, risk_score, scan_time, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        prediction,
        confidence,
        risk,
        risk_score,
        scan_time,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_scan_history():

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return scans


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_stats():

    connection = get_connection()
    cursor = connection.cursor()

    # Total scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
    """)
    total_scans = cursor.fetchone()[0]

    # Safe websites
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE prediction = 'Legitimate Website'
    """)
    safe_websites = cursor.fetchone()[0]

    # Phishing websites
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE prediction = 'Phishing Website'
    """)
    phishing_detected = cursor.fetchone()[0]

    # High risk websites
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE risk = 'High'
    """)
    high_risk = cursor.fetchone()[0]

    connection.close()

    return {
        "total_scans": total_scans,
        "safe_websites": safe_websites,
        "phishing_detected": phishing_detected,
        "high_risk": high_risk
    }