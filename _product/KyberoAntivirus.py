import os
import sys
import subprocess
import ssl
import pkgutil
import logging
import traceback
import json

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
        self.terminal.write(message)  # Also print to console
        self.log.write(message)  # Write to log file

    def flush(self):
        self.terminal.flush()
        self.log.flush()

# Redirect stdout and stderr to log file
sys.stdout = LogToFile(log_file)
sys.stderr = LogToFile(log_file)

# List of required modules (skip hashlib, json, base64, tkinter since they are built-in)
required_modules = [
    'requests',
    'urllib3',
    'charset_normalizer'
]

# Function to install missing modules
def install_module(module_name, version=None):
    try:
        if version:
            subprocess.check_call([sys.executable, "-m", "pip", "install", f"{module_name}=={version}"])
        else:
            subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to install {module_name}: {e}"
        print(error_msg)
        logging.error(error_msg)  # Log the error
        handle_error(e)

# Check if a module is part of the bundled PyInstaller executable
def is_module_bundled(module_name):
    # Check if the module can be found in the sys.modules or bundled package
    if module_name in sys.modules:
        return True
    if pkgutil.find_loader(module_name) is not None:
        return True
    return False

# Handle errors gracefully and prevent the app from closing immediately
def handle_error(error):
    error_msg = f"An error occurred: {str(error)}"
    print(error_msg)
    logging.error(error_msg)  # Log the error

    logging.error("Full traceback:")
    traceback.print_exc(file=sys.stdout)  # Log the full traceback to the file and console

    input("Press Enter to exit...")  # Pause before closing

# Check and install missing modules
def check_and_install_modules():
    for module in required_modules:
        if not is_module_bundled(module):
            module_msg = f"Module '{module}' not found. Installing..."
            print(module_msg)
            logging.info(module_msg)  # Log the info
            install_module(module)

# Check and install the correct version of urllib3
def check_urllib3_version():
    try:
        import urllib3
        if urllib3.__version__ >= '2.0.0':
            info_msg = f"urllib3 v{urllib3.__version__} found. Checking OpenSSL compatibility."
            print(info_msg)
            logging.info(info_msg)  # Log the info
            openssl_version = ssl.OPENSSL_VERSION
            if "1.1.1" not in openssl_version:
                warning_msg = f"Warning: OpenSSL version {openssl_version} is not compatible with urllib3 v2.0+."
                print(warning_msg)
                logging.warning(warning_msg)  # Log the warning
                print("Consider upgrading OpenSSL or downgrading urllib3.")
        else:
            info_msg = f"urllib3 v{urllib3.__version__} is compatible."
            print(info_msg)
            logging.info(info_msg)  # Log the info
    except ImportError:
        error_msg = "urllib3 is not installed. Installing a compatible version..."
        print(error_msg)
        logging.error(error_msg)  # Log the error
        install_module('urllib3', '1.26.10')  # Install a compatible version

# Main execution
try:
    # Check and install missing modules and verify compatibility
    check_and_install_modules()
    check_urllib3_version()

except Exception as e:
    handle_error(e)

# Your other imports and code can follow here
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import threading  # Import threading module

# Antivirus version
KYBERO_VERSION = "prototype 0.1.0 stable"

# Configurations
DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'threat_db.txt')
GITHUB_API_URL = "https://github.com/Kybero/Kybero-Antivirus/blob/main/dev/db/threat_db.txt?raw=true"
CLOUD_API_URL = "https://kybero-control.onrender.com/scan"  # Replace with your cloud API URL

# Quarantine directory
QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), 'quarantine')

# Function to check and update the local database
def check_and_update_threat_db():
    try:
        # Ensure the database directory exists
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        remote_db_content = None
        remote_hash = None

        if os.path.exists(DB_PATH):
            print("Local database found. Comparing with remote version...")
            response = requests.get(GITHUB_API_URL)
            if response.status_code != 200:
                print(f"Failed to fetch remote database. HTTP Status Code: {response.status_code}")
                return

            remote_db_content = response.content
            remote_hash = hashlib.sha256(remote_db_content).hexdigest()

            with open(DB_PATH, 'rb') as local_file:
                local_db_content = local_file.read()
                local_hash = hashlib.sha256(local_db_content).hexdigest()

                if local_hash == remote_hash:
                    print("Database is up-to-date.")
                    return
                else:
                    print("Database differs. Updating...")
        else:
            print("Local database not found. Downloading...")
            response = requests.get(GITHUB_API_URL)
            if response.status_code != 200:
                print(f"Failed to fetch remote database. HTTP Status Code: {response.status_code}")
                return

            remote_db_content = response.content

        # Overwrite the existing database file (or create it if not present)
        with open(DB_PATH, 'wb') as file:
            file.write(remote_db_content)
        print("Database updated successfully.")

    except requests.exceptions.RequestException as e:
        print(f"Error accessing the remote database: {e}")
        raise Exception(f"Error accessing the remote database: {e}")

# Load threat database (processing each line to extract relevant data)
def load_threat_db():
    global threat_db  # Ensure the function updates the global variable
    try:
        check_and_update_threat_db()
        print("Threat database loaded successfully.")
        with open(DB_PATH, 'r') as db_file:
            # Assume the file contains JSON data
            threat_db = json.load(db_file)
            print("Loaded threat database content.")
    except Exception as e:
        print(f"Error loading threat database: {e}")
    return threat_db
    
# Send file to cloud API for scanning
def scan_file_with_cloud_api(file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(CLOUD_API_URL, files=files)
            if response.status_code == 200:
                result = response.json()  # Assuming the response is in JSON format
                if result.get('threat_detected'):
                    print(f"Threat detected: {result['threat_name']} in {file_path}")
                    return result['threat_name'], file_path
                else:
                    print(f"No threat detected in {file_path}")
                    return None, None
            else:
                print(f"Error scanning file with cloud API. HTTP Status Code: {response.status_code}")
                return None, None
    except requests.exceptions.RequestException as e:
        print(f"Error accessing cloud API: {e}")
        return None, None

def check_threat_cloud(file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            print(f"Sending file {file_path} to cloud API...")
            
            response = requests.post(CLOUD_API_URL, files=files)
            
            print(f"Cloud API response: {response.status_code}, {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                if "threat_detected" in data and data["threat_detected"]:
                    print(f"Threat detected (cloud): {data['threat_name']}")
                    return data["threat_name"], file_path
                else:
                    print(f"No threat detected for: {file_path}")
                    return None, None
            else:
                print(f"Error from cloud API: {response.status_code} - {response.text}")
                return None, None
    
    except Exception as e:
        print(f"Error accessing cloud API: {e}")
        return None, None

# Modified function to check both cloud and local database for threats
def check_threat(file_hash, file_path, threat_db):
    if not threat_db:  # If threat_db is empty (database unavailable)
        print("No database available to check threats.")
        return None, None
    
    # First, check with the cloud API
    threat_name, found_hash = check_threat_cloud(file_path)
    if threat_name:
        # If a threat is found in the cloud, return the result
        return threat_name, found_hash
    
    # If no cloud threat is found, check the local database
    for entry in threat_db:
        if 'hashes' in entry and file_hash in entry['hashes']:
            print(f"Threat detected (local database): {file_path} (hash match) - {entry['name']}")
            return entry['name'], file_hash  # Return the threat name and file hash
    
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
        print(f"Permission denied: {file_path}")
        return None  # Return None if file can't be accessed
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return None  # Handle any other exceptions

# Scan a directory for threats
def scan_directory(path, threat_db, results_widget, progress_var, progress_label, progress_bar, current_file_label):
    threats_found = []
    total_files = sum([len(files) for _, _, files in os.walk(path)])
    scanned_files = 0

    if os.path.isfile(path):  # If it's a file
        file_hash = hash_file(path)
        file_name, hash_found = check_threat(file_hash, path, threat_db)
        if hash_found or file_name:
            threats_found.append((path, file_hash, file_name, hash_found))
        scanned_files += 1
        # Update the current file label
        current_file_label.config(text=f"Currently scanning: {path}")
        # Update the progress bar for single file scan
        progress_bar.after(0, update_progress, progress_var, scanned_files, total_files, results_widget, progress_label, progress_bar)

    elif os.path.isdir(path):  # If it's a directory
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = hash_file(file_path)
                file_name, hash_found = check_threat(file_hash, file_path, threat_db)
                if hash_found or file_name:
                    threats_found.append((file_path, file_hash, file_name, hash_found))  # Append each detected threat
                scanned_files += 1
                # Update the current file label
                current_file_label.config(text=f"Currently scanning: {file_path}")
                # Update the progress bar after scanning each file
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
        self.root.geometry("700x600")  # Increase the window size to accommodate logs
        
        # Center the window
        window_width = 700
        window_height = 600
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_left = int(screen_width / 2 - window_width / 2)
        self.root.geometry(f'{window_width}x{window_height}+{position_left}+{position_top}')
        
        # Add title
        self.title_label = ttk.Label(self.root, text="Kybero Antivirus", font=("Helvetica", 16))
        self.title_label.pack(pady=10)

        # Scan button
        self.scan_button = ttk.Button(self.root, text="Select File or Folder to Scan", command=self.select_file_or_folder, state=tk.NORMAL)
        self.scan_button.pack(pady=10)
        
        self.quarantine_button = ttk.Button(self.root, text="Manage Quarantine", command=self.manage_quarantine)
        self.quarantine_button.pack(pady=10)
        
        self.take_action_button = ttk.Button(self.root, text="Take Action", command=self.open_action_window, state=tk.DISABLED)
        self.take_action_button.pack(pady=10)

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
    # Create the welcome window
    root = tk.Tk()
    welcome_window = WelcomeWindow(root)
    root.mainloop()
