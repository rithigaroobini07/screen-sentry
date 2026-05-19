import sqlite3
import hashlib
import datetime
import os
from pathlib import Path

DB_PATH = "screensentry.db"

def get_connection():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Evidence table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            image_path TEXT NOT NULL,
            confidence REAL,
            severity TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'Pending',
            deleted INTEGER DEFAULT 0,
            hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Admin credentials table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Login attempts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

def compute_hash(data):
    """Compute SHA256 hash of data."""
    return hashlib.sha256(str(data).encode()).hexdigest()

def add_evidence(image_path, confidence, severity='Medium'):
    """Add evidence record to database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    record_data = f"{timestamp}|{image_path}|{confidence}|{severity}"
    record_hash = compute_hash(record_data)
    
    cursor.execute("""
        INSERT INTO evidence (timestamp, image_path, confidence, severity, hash)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, image_path, confidence, severity, record_hash))
    
    evidence_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit("Evidence Captured", f"Evidence ID: {evidence_id}, Path: {image_path}")
    return evidence_id

def get_all_evidence(include_deleted=False):
    """Get all evidence records."""
    conn = get_connection()
    cursor = conn.cursor()
    
    if include_deleted:
        cursor.execute("SELECT * FROM evidence ORDER BY timestamp DESC")
    else:
        cursor.execute("SELECT * FROM evidence WHERE deleted = 0 ORDER BY timestamp DESC")
    
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_deleted_evidence():
    """Get all deleted evidence (recycle bin)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence WHERE deleted = 1 ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def soft_delete_evidence(evidence_id):
    """Soft delete evidence (move to recycle bin)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET deleted = 1 WHERE id = ?", (evidence_id,))
    conn.commit()
    conn.close()
    log_audit("Evidence Deleted", f"Evidence ID: {evidence_id} moved to recycle bin")

def restore_evidence(evidence_id):
    """Restore evidence from recycle bin."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET deleted = 0 WHERE id = ?", (evidence_id,))
    conn.commit()
    conn.close()
    log_audit("Evidence Restored", f"Evidence ID: {evidence_id} restored from recycle bin")

def permanent_delete_evidence(evidence_id):
    """Permanently delete evidence."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get image path before deleting
    cursor.execute("SELECT image_path FROM evidence WHERE id = ?", (evidence_id,))
    row = cursor.fetchone()
    if row:
        image_path = row['image_path']
        # Delete from database
        cursor.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        conn.commit()
        # Delete physical file
        if os.path.exists(image_path):
            os.remove(image_path)
        log_audit("Evidence Permanently Deleted", f"Evidence ID: {evidence_id}, Path: {image_path}")
    
    conn.close()

def update_evidence_status(evidence_id, status):
    """Update evidence status (Pending/Confirmed/False Alarm)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET status = ? WHERE id = ?", (status, evidence_id))
    conn.commit()
    conn.close()
    log_audit("Evidence Status Updated", f"Evidence ID: {evidence_id}, Status: {status}")

def log_audit(action, details=""):
    """Log admin action to audit trail."""
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        INSERT INTO audit_log (timestamp, action, details)
        VALUES (?, ?, ?)
    """, (timestamp, action, details))
    conn.commit()
    conn.close()

def get_audit_logs(limit=100):
    """Get recent audit logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def verify_integrity():
    """Verify integrity of all evidence records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, image_path, confidence, severity, hash FROM evidence")
    rows = cursor.fetchall()
    
    tampered = []
    for row in rows:
        record_data = f"{row['timestamp']}|{row['image_path']}|{row['confidence']}|{row['severity']}"
        computed_hash = compute_hash(record_data)
        if computed_hash != row['hash']:
            tampered.append(row['id'])
    
    conn.close()
    
    if tampered:
        log_audit("Integrity Check Failed", f"Tampered evidence IDs: {tampered}")
    
    return tampered

def get_statistics():
    """Get evidence statistics for analytics."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total threats
    cursor.execute("SELECT COUNT(*) as total FROM evidence WHERE deleted = 0")
    total = cursor.fetchone()['total']
    
    # By status
    cursor.execute("SELECT status, COUNT(*) as count FROM evidence WHERE deleted = 0 GROUP BY status")
    by_status = {row['status']: row['count'] for row in cursor.fetchall()}
    
    # By severity
    cursor.execute("SELECT severity, COUNT(*) as count FROM evidence WHERE deleted = 0 GROUP BY severity")
    by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    # By date (last 7 days)
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count 
        FROM evidence 
        WHERE deleted = 0 AND DATE(timestamp) >= DATE('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    by_date = [(row['date'], row['count']) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        'total': total,
        'by_status': by_status,
        'by_severity': by_severity,
        'by_date': by_date
    }

# Initialize database on import
if __name__ == "__main__":
    init_database()
    print("Database initialized successfully!")
