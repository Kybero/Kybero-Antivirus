import os
import sys
import subprocess
import logging
import traceback
import json
import psutil
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import threading
from datetime import datetime, timedelta

# Configure logging
log_file = "log.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Redirect stdout and stderr to the log file
class LogToFile:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        # Write to console if terminal is available
        if self.terminal is not None:
            self.terminal.write(message)

        # Always write to the log file
        if self.log is not None:
            self.log.write(message)

    def flush(self):
        # Flush both terminal and log file outputs
        if self.terminal is not None:
            self.terminal.flush()
        if self.log is not None:
            self.log.flush()

# Redirect stdout and stderr to log file
sys.stdout = LogToFile(log_file)
sys.stderr = LogToFile(log_file)

# Handle errors gracefully and prevent the app from closing immediately
def handle_error(error):
    error_msg = f"An error occurred: {str(error)}"
    if sys.stdout:
        print(error_msg)
    logging.error(error_msg)  # Log the error

    logging.error("Full traceback:")
    traceback.print_exc(file=sys.stdout)  # Log the full traceback to the file and console

    input("Press Enter to exit...")  # Pause before closing

# Antivirus version
KYBERO_VERSION = "prototype 0.2.0 stable"

# Configurations
DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'threat_db.txt')
GITHUB_API_URL = "https://github.com/Kybero/Kybero-Antivirus/blob/main/dev/db/threat_db.txt?raw=true"
CLOUD_API_URL = "https://kybero-control.onrender.com/scan"  # Replace with your cloud API URL
CACHE_FILE = os.path.join(os.path.dirname(__file__), "cache.json")
CACHE_EXPIRATION_DAYS = 30

# Quarantine directory
QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), 'quarantine')

# Create the cache file immediately if it doesn't exist
if not os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "w") as f:
        json.dump({}, f)  # Create an empty JSON file
        
# Load cache from disk
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)
else:
    cache = {}
    
cache_file_path = os.path.abspath(CACHE_FILE)
if sys.stdout:
    print(f"Cache file will be established at: {cache_file_path}")

# def run_in_background(script_name):
#     # Get the full path of the component script
#     current_dir = os.path.dirname(os.path.abspath(__file__))
#     component_script_path = os.path.join(current_dir, script_name)
    
#     # Ensure the script is not run in the console window
#     startupinfo = subprocess.STARTUPINFO()
#     startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

#     # Run the component script in the background
#     subprocess.Popen([sys.executable, component_script_path], startupinfo=startupinfo)
#     if sys.stdout:
#         print("Real-time protection enabled.")
        
# def is_component_running(script_name):
#     for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
#         try:
#             # Ensure cmdline is not None before accessing it
#             if proc.info['cmdline'] and script_name in proc.info['cmdline']:
#                 return True
#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             pass  # Ignore any processes we can't access
#     return False

# Function to check and update the local database
def check_and_update_threat_db():
    try:
        # Ensure the database directory exists
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        remote_db_content = None
        remote_hash = None

        if os.path.exists(DB_PATH):
            if sys.stdout:
                print("Local database found. Comparing with remote version...")
            response = requests.get(GITHUB_API_URL)
            if response.status_code != 200:
                if sys.stdout:
                    print(f"Failed to fetch remote database. HTTP Status Code: {response.status_code}")
                return

            remote_db_content = response.content
            remote_hash = hashlib.sha256(remote_db_content).hexdigest()

            with open(DB_PATH, 'rb') as local_file:
                local_db_content = local_file.read()
                local_hash = hashlib.sha256(local_db_content).hexdigest()

                if local_hash == remote_hash:
                    if sys.stdout:
                        print("Database is up-to-date.")
                    return
                else:
                    if sys.stdout:
                        print("Database differs. Updating...")
        else:
            if sys.stdout:
                print("Local database not found. Downloading...")
            response = requests.get(GITHUB_API_URL)
            if response.status_code != 200:
                if sys.stdout:
                    print(f"Failed to fetch remote database. HTTP Status Code: {response.status_code}")
                return

            remote_db_content = response.content

        # Overwrite the existing database file (or create it if not present)
        with open(DB_PATH, 'wb') as file:
            file.write(remote_db_content)
        if sys.stdout:
            print("Database updated successfully at: {DB_PATH}")

    except requests.exceptions.RequestException as e:
        if sys.stdout:
            print(f"Error accessing the remote database: {e}")
        raise Exception(f"Error accessing the remote database: {e}")

# Load threat database (processing each line to extract relevant data)
def load_threat_db():
    global threat_db  # Ensure the function updates the global variable
    try:
        check_and_update_threat_db()
        if sys.stdout:
            print("Threat database loaded successfully.")
        with open(DB_PATH, 'r') as db_file:
            # Assume the file contains JSON data
            threat_db = json.load(db_file)
            if sys.stdout:
                print("Loaded threat database content.")
    except Exception as e:
        if sys.stdout:
            print(f"Error loading threat database: {e}")
    return threat_db

# Save cache to disk
def save_cache():
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

# Remove expired cache entries
def clean_expired_cache():
    now = datetime.now()
    expiration_date = now - timedelta(days=CACHE_EXPIRATION_DAYS)
    expired_keys = [k for k, v in cache.items() if datetime.fromisoformat(v['timestamp']) < expiration_date]
    for key in expired_keys:
        del cache[key]
    if expired_keys:
        save_cache()

# Hash a file
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

# Check the local cache before cloud scan
def check_local_cache(file_hash):
    clean_expired_cache()
    if file_hash in cache:
        entry = cache[file_hash]
        print(f"[CACHE] {entry['result']} - {entry['timestamp']}")
        return entry['result']
    return None
    
# Send file to cloud API if not in cache
def scan_file_with_cloud_api(file_path):
    file_hash = calculate_hash(file_path)

    # Check local cache first
    cached_result = check_local_cache(file_hash)
    if cached_result:
        return cached_result, file_path

    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            if sys.stdout:
                print("Uploading {file_path} to cloud...")
            response = requests.post(CLOUD_API_URL, files=files)
            if response.status_code == 200:
                result = response.json()
                scan_result = result.get('threat_name', 'clean')

                # Cache the result
                cache[file_hash] = {
                    "result": scan_result,
                    "timestamp": datetime.now().isoformat()
                }
                save_cache()

                if sys.stdout:
                    print(f"[CLOUD] Threat detected: {scan_result} in {file_path}")
                return scan_result, file_path
            else:
                if sys.stdout:
                    print(f"Error scanning file. Status: {response.status_code}")
                return None, None
    except requests.exceptions.RequestException as e:
        if sys.stdout:
            print(f"Error accessing cloud API: {e}")
        return None, None

def check_threat_cloud(file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            if sys.stdout:
                print(f"Sending file {file_path} to cloud API...")
            
            response = requests.post(CLOUD_API_URL, files=files)
            
            if sys.stdout:
                print(f"Cloud API response: {response.status_code}, {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                if "threat_detected" in data and data["threat_detected"]:
                    if sys.stdout:
                        print(f"Threat detected (cloud): {data['threat_name']}")
                    return data["threat_name"], file_path
                else:
                    if sys.stdout:
                        print(f"No threat detected for: {file_path}")
                    return None, None
            else:
                if sys.stdout:
                    print(f"Error from cloud API: {response.status_code} - {response.text}")
                return None, None
    
    except Exception as e:
        if sys.stdout:
            print(f"Error accessing cloud API: {e}")
        return None, None

# Check both local database and cloud for threats
def check_threat(file_hash, file_path, threat_db):
    cached_result = check_local_cache(file_hash)
    if cached_result:
        return cached_result, file_hash

    # Check local database
    for entry in threat_db:
        if 'hashes' in entry and file_hash in entry['hashes']:
            print(f"[LOCAL DB] Threat detected: {entry['name']} in {file_path}")
        
            # Cache the result if detected from the local database
            cache[file_hash] = {
                "result": entry['name'],
                "timestamp": datetime.now().isoformat()
            }
            save_cache()  # Save the cache file after updating it
            return entry['name'], file_hash

    # If not found locally, check cloud
    threat_name, found_hash = scan_file_with_cloud_api(file_path)
    return threat_name, found_hash
    
    # First, check with the cloud API
    threat_name, found_hash = check_threat_cloud(file_path)
    if threat_name:
        # If a threat is found in the cloud, return the result
        return threat_name, found_hash
    
    if sys.stdout:
        print(f"No threat detected for: {file_path}")
    return None, None

# Hash a file
def hash_file(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        if sys.stdout:
            print(f"Permission denied: {file_path}")
        return None  # Return None if file can't be accessed
    except Exception as e:
        if sys.stdout:
            print(f"Error processing file {file_path}: {e}")
        return None  # Handle any other exceptions

# Scan a directory for threats
def scan_directory(path, threat_db, results_widget, progress_var, progress_label, progress_bar, current_file_label):
    threats_found = []
    total_files = sum([len(files) for _, _, files in os.walk(path)])
    scanned_files = 0

    if os.path.isfile(path):  # If it's a single file
        file_hash = calculate_hash(path)
        threat_name, hash_found = check_threat(file_hash, path, threat_db)
        if threat_name and threat_name != 'clean':
            threats_found.append((path, file_hash, threat_name, hash_found))
        scanned_files += 1
        current_file_label.config(text=f"Currently scanning: {path}")
        progress_bar.after(0, update_progress, progress_var, scanned_files, total_files, results_widget, progress_label, progress_bar)

    elif os.path.isdir(path):  # If it's a directory
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = calculate_hash(file_path)
                threat_name, hash_found = check_threat(file_hash, file_path, threat_db)
                
                if threat_name and threat_name != 'clean':
                    threats_found.append((file_path, file_hash, threat_name, hash_found))
                scanned_files += 1

                current_file_label.config(text=f"Currently scanning: {file_path}")
                progress_bar.after(0, update_progress, progress_var, scanned_files, total_files, results_widget, progress_label, progress_bar)

    return threats_found

def update_progress(progress_var, scanned_files, total_files, results_widget, progress_label, progress_bar):
    # Check if the progress bar widget and window still exist before updating
    if progress_bar.winfo_exists() and results_widget.winfo_exists():
        progress = (scanned_files / total_files) * 100 if total_files > 0 else 0
        progress_var.set(progress)
        progress_label.config(text=f"{int(progress)}%")
        results_widget.update_idletasks()  # Update the results widget (text area)

# GUI for the antivirus program
class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Kybero Antivirus")
        self.root.geometry("700x480")  # Increase the window size to accommodate logs
        
        # Center the window
        window_width = 700
        window_height = 480
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_left = int(screen_width / 2 - window_width / 2)
        self.root.geometry(f'{window_width}x{window_height}+{position_left}+{position_top}')
        
        # Add title
        self.title_label = ttk.Label(self.root, text="Kybero Antivirus", font=("Helvetica", 16))
        self.title_label.pack(pady=10)

        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Scan File or Folder", command=self.select_file_or_folder, state=tk.NORMAL)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.quarantine_button = ttk.Button(button_frame, text="Manage Quarantine", command=self.manage_quarantine)
        self.quarantine_button.pack(side=tk.LEFT, padx=5)
        
        self.take_action_button = ttk.Button(button_frame, text="Take Action", command=self.open_action_window, state=tk.DISABLED)
        self.take_action_button.pack(side=tk.LEFT, padx=5)

        # Results area
        self.results_label = ttk.Label(self.root, text="Scan Results:")
        self.results_label.pack(pady=5)
        
        self.results_text = tk.Text(self.root, height=10, width=70)  # Use tk.Text instead of ttk.Text
        self.results_text.pack(pady=5)

        # Progress Bar
        self.progress_label = ttk.Label(self.root, text="Scan Progress:")
        self.progress_label.pack(pady=5)

        self.progress_var = tk.DoubleVar()  # Use tk.DoubleVar() instead of ttk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=5)

        # Percentage display
        self.percentage_label = ttk.Label(self.root, text="0%")
        self.percentage_label.pack(pady=5)
        
        # Current file label
        self.current_file_label = ttk.Label(self.root, text="Currently scanning: None")
        self.current_file_label.pack(pady=5)
        
        # Version label in bottom right
        self.version_label = ttk.Label(self.root, text=f"Version: {KYBERO_VERSION}")
        self.version_label.pack(side=tk.BOTTOM, anchor=tk.SE, padx=10, pady=10)

        # Thread for loading database
        self.load_db_thread = threading.Thread(target=self.load_database, daemon=True)
        self.load_db_thread.start()
        
        # To store detected threats
        self.detected_threats = []

    def load_database(self):
        global threat_db
        threat_db = load_threat_db()
        
    def manage_quarantine(self):
        # Ensure the quarantine directory exists
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        
        # Open the quarantine folder
        os.startfile(QUARANTINE_DIR)
    
    def select_file_or_folder(self):
        # Ask the user to choose between file or folder
        user_choice = tk.messagebox.askquestion("Select File or Folder", "Do you want to scan a file?", icon='question')
    
        if user_choice == 'yes':
            file_path = filedialog.askopenfilename(title="Select a file to scan")
            if file_path:
                # Run the scan in a separate thread to avoid blocking the GUI
                scanning_thread = threading.Thread(target=self.run_scan, args=(file_path,), daemon=True)
                scanning_thread.start()
        else:
            folder_path = filedialog.askdirectory(title="Select a folder to scan")
            if folder_path:
                # Run the scan in a separate thread to avoid blocking the GUI
                scanning_thread = threading.Thread(target=self.run_scan, args=(folder_path,), daemon=True)
                scanning_thread.start()

    def run_scan(self, path):
        threats = scan_directory(path, threat_db, self.results_text, self.progress_var, self.percentage_label, self.progress_bar, self.current_file_label)
        self.display_results(threats)

    def display_results(self, threats):
        self.results_text.delete(1.0, tk.END)  # Clear existing text
        self.detected_threats = threats  # Store the detected threats
        if threats:
            for threat in threats:
                # Display threat name along with file path and hash
                self.results_text.insert(tk.END, f"Threat detected: {threat[2]} in file {threat[0]} with hash {threat[1]}\n")
                self.take_action_button.config(state=tk.NORMAL)
        else:
            self.results_text.insert(tk.END, "No threats detected.\n")
            self.take_action_button.config(state=tk.DISABLED)  # Disable the button if no threats
            
    def open_action_window(self):
        if self.detected_threats:
            action_window = tk.Toplevel(self.root)
            action_window.title("Take Action")
            action_window.geometry("400x300")
            action_label = ttk.Label(action_window, text="Choose action for detected threats:")
            action_label.pack(pady=10)
            # List the threats in the action window
            for threat in self.detected_threats:
                threat_label = ttk.Label(action_window, text=f"Threat: {threat[2]} in {threat[0]}")
                threat_label.pack(pady=5)
            action_frame = ttk.Frame(action_window)
            action_frame.pack(pady=20)
            # Add buttons for each action
            delete_button = ttk.Button(action_frame, text="Delete All", command=self.delete_all_threats)
            delete_button.pack(side=tk.LEFT, padx=10)
            quarantine_button = ttk.Button(action_frame, text="Quarantine All", command=self.quarantine_all_threats)
            quarantine_button.pack(side=tk.LEFT, padx=10)
            ignore_button = ttk.Button(action_frame, text="Ignore All", command=self.ignore_all_threats)
            ignore_button.pack(side=tk.LEFT, padx=10)
            
    def delete_all_threats(self):
        for threat in self.detected_threats:
            self.delete_threat(threat[0])
        self.detected_threats.clear()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "All detected threats have been deleted.")
        
    def quarantine_all_threats(self):
        for threat in self.detected_threats:
            self.quarantine_threat(threat[0])
        self.detected_threats.clear()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "All detected threats have been quarantined.")
        
    def ignore_all_threats(self):
        self.detected_threats.clear()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "All detected threats have been ignored.")

    def delete_threat(self, file_path):
        try:
            os.remove(file_path)
            messagebox.showinfo("Success", f"The file {file_path} has been deleted.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete {file_path}: {e}")

    def quarantine_threat(self, file_path):
        try:
            quarantine_folder = os.path.join(os.path.dirname(__file__), 'quarantine')
            os.makedirs(quarantine_folder, exist_ok=True)
            quarantine_path = os.path.join(quarantine_folder, os.path.basename(file_path))
            os.rename(file_path, quarantine_path)
            messagebox.showinfo("Success", f"The file {file_path} has been quarantined.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to quarantine {file_path}: {e}")

    def ignore_threat(self, file_path):
        messagebox.showinfo("Ignored", f"The file {file_path} has been ignored.")

# Welcome window with loading bar
class WelcomeWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Kybero Antivirus - Loading")
        self.root.geometry("400x130")
        
        # Center the welcome window
        window_width = 400
        window_height = 130
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_left = int(screen_width / 2 - window_width / 2)
        self.root.geometry(f'{window_width}x{window_height}+{position_left}+{position_top}')
        
        # Welcome message
        self.welcome_label = ttk.Label(self.root, text="Welcome to Kybero Antivirus!", font=("Helvetica", 14))
        self.welcome_label.pack(pady=20)

        # Progress bar for loading
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=300, mode="indeterminate")
        self.progress_bar.pack(pady=10)
        self.progress_bar.start()

        # Start loading in background thread
        self.load_thread = threading.Thread(target=self.start_main_window, daemon=True)
        self.load_thread.start()

    def start_main_window(self):
        # Simulate loading process
        import time
        time.sleep(3)  # Simulate loading for 3 seconds

        # After loading, switch to the main window
        self.root.after(0, self.open_main_window)

    def open_main_window(self):
        # Destroy the welcome window and open the main window
        self.root.destroy()
        main_root = tk.Tk()
        AntivirusGUI(main_root)
        main_root.mainloop()


if __name__ == "__main__":
    # script_name = "KyberoAVbg.py"
    
    # if is_component_running(script_name):
    #     print("Component is already running. Exiting...")
    #     sys.exit(0)
    # else:
    #     run_in_background(script_name)
    
    # Create the welcome window
    root = tk.Tk()
    welcome_window = WelcomeWindow(root)
    root.mainloop()
