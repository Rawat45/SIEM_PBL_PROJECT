from flask import Flask, request, render_template, redirect, jsonify
import sqlite3
import datetime
import os
import re
import json
import logging
from collections import deque, Counter
from datetime import datetime, timedelta
import threading
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='siem_server.log'
)

app = Flask(__name__)
DB_FILE = "logs.db"

# Configuration
ALERT_KEYWORDS = ["sudo", "failed", "unauthorized", "root login", "permission denied"]
LOG_SEVERITY_PATTERNS = {
    "CRITICAL": r"(critical|fatal|emergency)",
    "ERROR": r"(error|fail|denied)",
    "WARNING": r"(warning|warn|could not)",
    "INFO": r"(info|notice|started|stopped)",
    "DEBUG": r"(debug|trace)"
}

# Anomaly detection configuration
ANOMALY_CONFIG = {
    "time_window_minutes": 5,
    "error_threshold": 5,
    "auth_failure_threshold": 3,
    "suspicious_ip_threshold": 3,
    "rapid_events_threshold": 10,
    "baseline_period_days": 7
}

# Global state for anomalies
anomaly_state = {
    "last_anomalies": deque(maxlen=100),
    "ip_counters": Counter(),
    "auth_failure_counters": Counter(),
    "event_rate": deque(maxlen=100),
    "baselines": {}
}

# Lock for thread safety
db_lock = threading.Lock()

def init_db():
    """Initialize the database with properly indexed tables"""
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            # Main logs table
            c.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id TEXT UNIQUE,
                    timestamp TEXT,
                    log_line TEXT,
                    source TEXT,
                    severity TEXT,
                    processed INTEGER DEFAULT 0
                )
            """)
            
            # Alerts table
            c.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    message TEXT,
                    source TEXT,
                    severity TEXT,
                    related_log_id INTEGER,
                    FOREIGN KEY (related_log_id) REFERENCES logs(id)
                )
            """)
            
            # Anomalies table
            c.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    type TEXT,
                    message TEXT,
                    count INTEGER,
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)
            
            # Create indexes for better performance
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_processed ON logs(processed)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_log_id ON logs(log_id)")
            
            conn.commit()

def determine_severity(log_line):
    """Determine the severity of a log entry based on content"""
    log_line_lower = log_line.lower()
    
    for severity, pattern in LOG_SEVERITY_PATTERNS.items():
        if re.search(pattern, log_line_lower):
            return severity
    
    return "INFO"  # Default severity

def parse_timestamp(log_line):
    """
    Parse timestamp from log line with multiple format support
    Returns a datetime object or None if parsing fails
    """
    # Common timestamp patterns in logs
    patterns = [
        # May 19 23:58:46
        (r"^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})", "%b %d %H:%M:%S"),
        # 2023-05-19 23:58:46
        (r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
        # 19/May/2023:23:58:46
        (r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})", "%d/%b/%Y:%H:%M:%S")
    ]
    
    for pattern, time_format in patterns:
        match = re.search(pattern, log_line)
        if match:
            try:
                dt = datetime.strptime(match.group(1), time_format)
                # Add current year if not present in the timestamp
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
    
    # If no pattern matches, use current time
    return datetime.now()

def extract_ip_addresses(log_line):
    """Extract IP addresses from a log line"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, log_line)

def is_authentication_failure(log_line):
    """Check if the log line indicates an authentication failure"""
    auth_fail_patterns = [
        r'failed password',
        r'authentication failure',
        r'login failed',
        r'incorrect password',
        r'unauthorized'
    ]
    log_line_lower = log_line.lower()
    return any(re.search(pattern, log_line_lower) for pattern in auth_fail_patterns)

def detect_anomalies(log_entries):
    """
    Detect anomalies in real-time from incoming logs
    Returns a list of detected anomalies
    """
    anomalies = []
    now = datetime.now()
    
    # Track IP addresses
    for entry in log_entries:
        log_line = entry.get("log_line", "")
        timestamp = datetime.strptime(entry.get("timestamp"), "%Y-%m-%d %H:%M:%S")
        
        # Extract IPs
        ips = extract_ip_addresses(log_line)
        for ip in ips:
            anomaly_state["ip_counters"][ip] += 1
            
            # Check for suspicious IP activity
            if anomaly_state["ip_counters"][ip] >= ANOMALY_CONFIG["suspicious_ip_threshold"]:
                anomalies.append({
                    "type": "suspicious_ip",
                    "message": f"Suspicious activity from IP {ip}: {anomaly_state['ip_counters'][ip]} occurrences",
                    "count": anomaly_state["ip_counters"][ip],
                    "first_seen": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": now.strftime("%Y-%m-%d %H:%M:%S")
                })
                # Reset counter to avoid repeated alerts
                anomaly_state["ip_counters"][ip] = 0
        
        # Check for authentication failures
        if is_authentication_failure(log_line):
            source = entry.get("source", "unknown")
            anomaly_state["auth_failure_counters"][source] += 1
            
            if anomaly_state["auth_failure_counters"][source] >= ANOMALY_CONFIG["auth_failure_threshold"]:
                anomalies.append({
                    "type": "auth_failure",
                    "message": f"Multiple authentication failures from {source}: {anomaly_state['auth_failure_counters'][source]} attempts",
                    "count": anomaly_state["auth_failure_counters"][source],
                    "first_seen": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": now.strftime("%Y-%m-%d %H:%M:%S")
                })
                # Reset counter to avoid repeated alerts
                anomaly_state["auth_failure_counters"][source] = 0
    
    # Track event rate for spike detection
    event_count = len(log_entries)
    anomaly_state["event_rate"].append((now, event_count))
    
    # Clean up old event rate entries
    cutoff_time = now - timedelta(minutes=ANOMALY_CONFIG["time_window_minutes"])
    while anomaly_state["event_rate"] and anomaly_state["event_rate"][0][0] < cutoff_time:
        anomaly_state["event_rate"].popleft()
    
    # Check for event rate spikes
    if len(anomaly_state["event_rate"]) > 1:
        total_events = sum(count for _, count in anomaly_state["event_rate"])
        avg_rate = total_events / len(anomaly_state["event_rate"])
        
        # Get baseline rate if available
        current_hour = now.hour
        baseline_key = f"{now.weekday()}_{current_hour}"
        baseline_rate = anomaly_state["baselines"].get(baseline_key, avg_rate)
        
        # Update baseline
        if baseline_key not in anomaly_state["baselines"]:
            anomaly_state["baselines"][baseline_key] = avg_rate
        else:
            # Smooth update of baseline
            anomaly_state["baselines"][baseline_key] = (0.9 * anomaly_state["baselines"][baseline_key]) + (0.1 * avg_rate)
        
        # Check for significant deviation from baseline
        if avg_rate > baseline_rate * 2 and total_events > ANOMALY_CONFIG["rapid_events_threshold"]:
            anomalies.append({
                "type": "event_spike",
                "message": f"Event rate spike detected: {total_events} events in {ANOMALY_CONFIG['time_window_minutes']} minutes (baseline: {int(baseline_rate)} events)",
                "count": total_events,
                "first_seen": anomaly_state["event_rate"][0][0].strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": now.strftime("%Y-%m-%d %H:%M:%S")
            })
    
    # Store detected anomalies
    for anomaly in anomalies:
        anomaly_state["last_anomalies"].append(anomaly)
        save_anomaly_to_db(anomaly)
    
    return anomalies

def save_anomaly_to_db(anomaly):
    """Save a detected anomaly to the database"""
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO anomalies (timestamp, type, message, count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    anomaly.get("type", "unknown"),
                    anomaly.get("message", ""),
                    anomaly.get("count", 0),
                    anomaly.get("first_seen", ""),
                    anomaly.get("last_seen", "")
                )
            )
            conn.commit()

def check_for_alerts(log_entries):
    """Check log entries for alert conditions and save alerts to DB"""
    alerts = []
    
    for entry in log_entries:
        log_line = entry.get("log_line", "").lower()
        source = entry.get("source", "unknown")
        log_id = entry.get("id", 0)
        
        # Check for keyword-based alerts
        for keyword in ALERT_KEYWORDS:
            if keyword.lower() in log_line:
                severity = "HIGH" if keyword in ["sudo", "root login", "unauthorized"] else "MEDIUM"
                alert = {
                    "timestamp": entry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "message": f"Alert triggered by keyword '{keyword}': {log_line}",
                    "source": source,
                    "severity": severity,
                    "related_log_id": log_id
                }
                alerts.append(alert)
                save_alert_to_db(alert)
                break  # Only trigger one alert per log entry
    
    return alerts

def save_alert_to_db(alert):
    """Save an alert to the database"""
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO alerts (timestamp, message, source, severity, related_log_id) VALUES (?, ?, ?, ?, ?)",
                (
                    alert.get("timestamp", ""),
                    alert.get("message", ""),
                    alert.get("source", ""),
                    alert.get("severity", ""),
                    alert.get("related_log_id", 0)
                )
            )
            conn.commit()

def save_logs_to_db(logs):
    """Save multiple log entries to the database with duplicate detection"""
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            for log in logs:
                # Extract timestamp from log line if available
                log_timestamp = log.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                log_line = log.get("log_line", "")
                source = log.get("source", "unknown")
                log_id = log.get("id", "")
                severity = determine_severity(log_line)
                
                # Check for duplicate logs
                c.execute("SELECT id FROM logs WHERE log_id = ?", (log_id,))
                if not c.fetchone():  # Only insert if not a duplicate
                    c.execute(
                        "INSERT INTO logs (log_id, timestamp, log_line, source, severity) VALUES (?, ?, ?, ?, ?)",
                        (log_id, log_timestamp, log_line, source, severity)
                    )
            conn.commit()

# Define routes
@app.route("/")
def index():
    """Main dashboard route"""
    keyword = request.args.get("search", "")
    severity = request.args.get("severity", "")
    time_range = request.args.get("time_range", "24h")
    source = request.args.get("source", "")
    
    # Parse time range
    end_time = datetime.now()
    if time_range == "1h":
        start_time = end_time - timedelta(hours=1)
    elif time_range == "6h":
        start_time = end_time - timedelta(hours=6)
    elif time_range == "7d":
        start_time = end_time - timedelta(days=7)
    elif time_range == "30d":
        start_time = end_time - timedelta(days=30)
    else:  # Default to 24h
        start_time = end_time - timedelta(hours=24)
    
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Build query conditions
    query_conditions = ["timestamp >= ?"]
    query_params = [start_time_str]
    
    if keyword:
        query_conditions.append("log_line LIKE ?")
        query_params.append(f"%{keyword}%")
    
    if severity:
        query_conditions.append("severity = ?")
        query_params.append(severity)
    
    if source:
        query_conditions.append("source = ?")
        query_params.append(source)
    
    query_where = " AND ".join(query_conditions)
    
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # Get filtered logs
        c.execute(
            f"SELECT timestamp, log_line, source, severity FROM logs WHERE {query_where} ORDER BY timestamp DESC LIMIT 1000",
            query_params
        )
        logs = c.fetchall()
        
        # Get available sources for filtering
        c.execute("SELECT DISTINCT source FROM logs")
        sources = [row[0] for row in c.fetchall()]
        
        # Get recent alerts
        c.execute("SELECT timestamp, message, source, severity FROM alerts ORDER BY timestamp DESC LIMIT 10")
        recent_alerts = c.fetchall()
    
    return render_template(
        "dashboard.html",
        logs=logs,
        keyword=keyword,
        severity=severity,
        time_range=time_range,
        sources=sources,
        selected_source=source,
        recent_alerts=recent_alerts
    )

@app.route("/alerts")
def alerts():
    """Alerts display route"""
    severity = request.args.get("severity", "")
    time_range = request.args.get("time_range", "24h")
    
    # Parse time range
    end_time = datetime.now()
    if time_range == "1h":
        start_time = end_time - timedelta(hours=1)
    elif time_range == "6h":
        start_time = end_time - timedelta(hours=6)
    elif time_range == "7d":
        start_time = end_time - timedelta(days=7)
    elif time_range == "30d":
        start_time = end_time - timedelta(days=30)
    else:  # Default to 24h
        start_time = end_time - timedelta(hours=24)
    
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Build query conditions
    query_conditions = ["timestamp >= ?"]
    query_params = [start_time_str]
    
    if severity:
        query_conditions.append("severity = ?")
        query_params.append(severity)
    
    query_where = " AND ".join(query_conditions)
    
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            f"SELECT timestamp, message, source, severity FROM alerts WHERE {query_where} ORDER BY timestamp DESC",
            query_params
        )
        alerts_list = c.fetchall()
    
    return render_template("alerts.html", alerts=alerts_list, severity=severity, time_range=time_range)

@app.route("/anomalies")
def anomalies():
    """Anomalies display route"""
    time_range = request.args.get("time_range", "24h")
    anomaly_type = request.args.get("type", "")
    
    # Parse time range
    end_time = datetime.now()
    if time_range == "1h":
        start_time = end_time - timedelta(hours=1)
    elif time_range == "6h":
        start_time = end_time - timedelta(hours=6)
    elif time_range == "7d":
        start_time = end_time - timedelta(days=7)
    elif time_range == "30d":
        start_time = end_time - timedelta(days=30)
    else:  # Default to 24h
        start_time = end_time - timedelta(hours=24)
    
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Build query conditions
    query_conditions = ["timestamp >= ?"]
    query_params = [start_time_str]
    
    if anomaly_type:
        query_conditions.append("type = ?")
        query_params.append(anomaly_type)
    
    query_where = " AND ".join(query_conditions)
    
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            f"SELECT id, timestamp, type, message, count, first_seen, last_seen FROM anomalies WHERE {query_where} ORDER BY timestamp DESC",
            query_params
        )
        anomalies_list = []
        for row in c.fetchall():
            anomalies_list.append({
                "id": row[0],
                "time": row[1],
                "type": row[2],
                "message": row[3],
                "count": row[4],
                "first_seen": row[5],
                "last_seen": row[6]
            })
        
        # Get available anomaly types
        c.execute("SELECT DISTINCT type FROM anomalies")
        types = [row[0] for row in c.fetchall()]
    
    return render_template(
        "anomalies.html",
        anomalies=anomalies_list,
        time_range=time_range,
        types=types,
        selected_type=anomaly_type
    )

@app.route("/ingest", methods=["POST"])
def ingest():
    """Endpoint to receive logs from collectors"""
    try:
        data = request.json
        
        # Handle both single log and batch formats
        if "log_line" in data:
            # Single log format
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_line = data.get("log_line", "")
            source = data.get("source", "unknown")
            
            logs = [{
                "id": f"{source}_{timestamp}_{hash(log_line) % 10000}",
                "timestamp": timestamp,
                "log_line": log_line,
                "source": source
            }]
        elif "logs" in data:
            # Batch format
            logs = data.get("logs", [])
        else:
            return jsonify({"status": "error", "message": "Invalid log format"}), 400
        
        # Process logs
        save_logs_to_db(logs)
        alerts = check_for_alerts(logs)
        anomalies = detect_anomalies(logs)
        
        return jsonify({
            "status": "ok",
            "processed": len(logs),
            "alerts": len(alerts),
            "anomalies": len(anomalies)
        })
    except Exception as e:
        logging.error(f"Error processing logs: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/update_logs")
def update_logs():
    """API endpoint for real-time log updates"""
    last_id = request.args.get("last_id", "0")
    try:
        last_id = int(last_id)
    except ValueError:
        last_id = 0
    
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, timestamp, log_line, source, severity FROM logs WHERE id > ? ORDER BY id DESC LIMIT 100",
            (last_id,)
        )
        logs = [
            {
                "id": row[0],
                "timestamp": row[1],
                "log_line": row[2],
                "source": row[3],
                "severity": row[4]
            }
            for row in c.fetchall()
        ]
    
    return jsonify({"logs": logs})

@app.route("/api/update_alerts")
def update_alerts():
    """API endpoint for real-time alert updates"""
    last_id = request.args.get("last_id", "0")
    try:
        last_id = int(last_id)
    except ValueError:
        last_id = 0
    
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, timestamp, message, source, severity FROM alerts WHERE id > ? ORDER BY id DESC LIMIT 100",
            (last_id,)
        )
        alerts = [
            {
                "id": row[0],
                "timestamp": row[1],
                "message": row[2],
                "source": row[3],
                "severity": row[4]
            }
            for row in c.fetchall()
        ]
    
    return jsonify({"alerts": alerts})

# Background cleanup task
def cleanup_old_logs():
    """Periodic cleanup of old logs"""
    while True:
        try:
            cutoff_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
            with db_lock:
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date,))
                    conn.commit()
            logging.info(f"Cleaned up old logs before {cutoff_date}")
        except Exception as e:
            logging.error(f"Error in cleanup task: {e}")
        
        # Sleep for 1 day before next cleanup
        time.sleep(86400)