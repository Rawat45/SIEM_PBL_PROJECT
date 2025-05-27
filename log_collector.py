import requests
import time
import os
import socket
import json
import hashlib
from datetime import datetime
import logging
# Configure logging for the collector itself
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='collector.log'
)

# Configuration
LOG_FILE_PATH = "/var/log/system.log"  
SERVER_URL = "http://localhost:5020/ingest"
BATCH_SIZE = 10  # Number of logs to batch before sending
POSITION_FILE = ".log_position"  # File to track position between restarts
RETRY_INTERVAL = 5  # Seconds between retries on connection failure
MAX_RETRIES = 3  # Maximum number of retries for sending logs

def get_last_position():
    """Load the last read position from the position file"""
    try:
        if os.path.exists(POSITION_FILE):
            with open(POSITION_FILE, "r") as f:
                return int(f.read().strip())
    except Exception as e:
        logging.error(f"Error reading position file: {e}")
    return 0

def save_position(position):
    """Save the current read position to the position file"""
    try:
        with open(POSITION_FILE, "w") as f:
            f.write(str(position))
    except Exception as e:
        logging.error(f"Error saving position: {e}")

def tail_f(file, start_position=0):
    """
    Generator to read new lines from a file as they are added.
    Supports starting from a specific position and handles file rotation.
    """
    file.seek(start_position)
    
    while True:
        current_position = file.tell()
        line = file.readline()
        
        if line:
            yield current_position, line.strip()
        else:
            # Check if file has been rotated
            try:
                file_size = os.path.getsize(LOG_FILE_PATH)
                if file_size < current_position:
                    logging.info("Log rotation detected, reopening file")
                    file.close()
                    file = open(LOG_FILE_PATH, "r")
                    current_position = 0
                    file.seek(current_position)
            except Exception as e:
                logging.error(f"Error handling file rotation: {e}")
            
            time.sleep(0.5)

def generate_log_id(log_line, source):
    """Generate a unique ID for a log entry to avoid duplicates"""
    hash_input = f"{log_line}{source}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    return hashlib.md5(hash_input.encode()).hexdigest()

def send_logs(logs_batch):
    """Send a batch of logs to the server with retry logic"""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'SIEM-Log-Collector/1.0'
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Attempt {attempt + 1}: Sending {len(logs_batch)} logs")  # Debug
            
            response = requests.post(
                SERVER_URL,
                json={"logs": logs_batch},
                headers=headers,
                timeout=5
            )
            
            print(f"Response status: {response.status_code}")  # Debug
            print(f"Response content: {response.text}")  # Debug
            
            if response.status_code == 200:
                logging.info(f"Successfully sent {len(logs_batch)} logs")
                return True
            else:
                logging.warning(f"Failed to send logs: HTTP {response.status_code}, Response: {response.text}")
                
        except Exception as e:
            logging.error(f"Exception sending logs (attempt {attempt + 1}/{MAX_RETRIES}): {str(e)}")
        
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_INTERVAL)
    
    return False
def main():
    """Main function to collect and send logs"""
    logging.info(f"Starting log collector for {LOG_FILE_PATH}")
    hostname = socket.gethostname()
    
    # Handle file not found gracefully
    if not os.path.exists(LOG_FILE_PATH):
        logging.error(f"Log file {LOG_FILE_PATH} not found. Exiting.")
        return
    
    # Get the last read position
    last_position = get_last_position()
    logging.info(f"Starting from position {last_position}")
    
    logs_batch = []
    try:
        with open(LOG_FILE_PATH, "r") as logfile:
            for position, line in tail_f(logfile, last_position):
                # Process the log line
                log_id = generate_log_id(line, hostname)
                log_entry = {
                    "id": log_id,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "log_line": line,
                    "source": hostname
                }
                
                logs_batch.append(log_entry)
                logging.debug(f"Collected log: {line}")
                
                # Send logs in batches or when the batch is full
                if len(logs_batch) >= BATCH_SIZE:
                    if send_logs(logs_batch):
                        save_position(position)
                        logs_batch = []
    except KeyboardInterrupt:
        logging.info("Log collector stopped by user")
        # Send any remaining logs before exiting
        if logs_batch:
            send_logs(logs_batch)
    except Exception as e:
        logging.error(f"Fatal error in log collector: {e}")
        # Try to send any collected logs before exiting
        if logs_batch:
            send_logs(logs_batch)

if __name__ == "__main__":
    main()
