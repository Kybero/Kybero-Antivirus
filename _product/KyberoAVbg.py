import os
import sys
import time
import hashlib
import plyer
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Threat database and monitoring paths
SHA256_DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'threat_db.txt')
MONITOR_DIRS = ['C:/']  # Update with directories to monitor

# Load SHA256 threat hashes
def load_sha256_database():
    if os.path.exists(SHA256_DB_PATH):
        with open(SHA256_DB_PATH, 'r') as db:
            data = json.load(db)  # Load the JSON data

            # Iterate through each threat and extract the hashes
            threat_hashes = set()
            for threat in data:
                if "hashes" in threat:
                    threat_hashes.update(threat["hashes"])  # Add all hashes to the set
            
            return threat_hashes
    return set()

threat_hashes = load_sha256_database()

# Function to send notifications that trigger Kybero Antivirus on click
def send_notification(title, message):
    plyer.notification.notify(
        title=title,
        message=message,
        app_name='Kybero Antivirus',
        timeout=10
    )

# Function to scan a file for threats
def scan_file(filepath):
    try:
        hash_sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            chunk = f.read(8192)  # Read 8 KB chunk
            while chunk:
                hash_sha256.update(chunk)
                chunk = f.read(8192)  # Read the next chunk
        
        file_hash = hash_sha256.hexdigest()
        if file_hash in threat_hashes:
            send_notification("Kybero | Threat detected", f"File: {filepath}\nIt is recommended to perform a scan.")
            if sys.stdout:
                print(f"Threat detected in {filepath}: {file_hash}")
        else:
            if sys.stdout:
                print(f"No threat detected in {filepath} ({file_hash})")
    except PermissionError:
        pass
    except Exception as e:
        if sys.stdout:
            print(f"Error scanning {filepath}: {e}")

# Define a handler for file system events
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        try:
            if not event.is_directory:
                scan_file(event.src_path)  # Scan modified file
        except PermissionError:
            pass  # Ignore permission errors
            

    def on_created(self, event):
        try:
            if not event.is_directory:
                scan_file(event.src_path)  # Scan newly created file
        except PermissionError:
            pass  # Ignore permission errors

# Setup watchdog observer to monitor directories
def start_watchdog():
    event_handler = FileChangeHandler()
    observer = Observer()
    for dir_path in MONITOR_DIRS:
        observer.schedule(event_handler, dir_path, recursive=True)  # Monitor directories recursively
    observer.start()
    if sys.stdout:
        print("Real-time protection started.")
    try:
        while True:
            time.sleep(1)  # Keep the program running to monitor file changes
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    if threat_hashes:
        if sys.stdout:
            print(f"{threat_hashes}")
        start_watchdog()
    else:
        if sys.stdout:
            print("Real-time protection disabled due to database error.")