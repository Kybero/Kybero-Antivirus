import os
import hashlib
import json
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import threading  # Import threading module

# Configurations
DB_URL = "https://download-files.wixmp.com/raw/a034b7_d0b7473dfa1b46a78afdd6f9ec431a5e.txt?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46YXBwOmU2NjYzMGU3MTRmMDQ5MGFhZWExZjE0OWIzYjY5ZTMyIiwic3ViIjoidXJuOmFwcDplNjY2MzBlNzE0ZjA0OTBhYWVhMWYxNDliM2I2OWUzMiIsImF1ZCI6WyJ1cm46c2VydmljZTpmaWxlLmRvd25sb2FkIl0sImlhdCI6MTczNDk1NDc5NCwiZXhwIjoxNzM0OTU1NzA0LCJqdGkiOiI1NmE4ZGYzYy1jOTlhLTQyNDEtODA1OC0zNDEwYjIyMTBlZGEiLCJvYmoiOltbeyJwYXRoIjoiL3Jhdy9hMDM0YjdfZDBiNzQ3M2RmYTFiNDZhNzhhZmRkNmY5ZWM0MzFhNWUudHh0In1dXSwiZGlzIjp7ImZpbGVuYW1lIjoidGhyZWF0X2RiLnR4dCIsInR5cGUiOiJpbmxpbmUifX0.Izu0LqLMcrY3L14VuIoLm2WTj-F3Cf9Tz2kATOEUzIg"
DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'threat_db.txt')

# Download threat database
def download_threat_db():
    response = requests.get(DB_URL)
    if response.status_code == 200:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with open(DB_PATH, 'wb') as file:
            file.write(response.content)
        print("Database updated successfully.")
    else:
        print("Failed to download database.")

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

# Load threat database
def load_threat_db():
    if not os.path.exists(DB_PATH):
        print("Threat database not found. Downloading...")
        download_threat_db()
    
    with open(DB_PATH, 'r') as f:
        content = f.read()
        try:
            db = json.loads(content)
            print("Threat database loaded successfully.")
            return db
        except json.JSONDecodeError:
            print("Error decoding threat database. Ensure it is properly formatted.")
            return []

# Check if a file hash is a threat
def check_threat(file_hash):
    for entry in threat_db:
        if 'hashes' in entry and file_hash in entry['hashes']:
            print(f"Threat detected: {entry['name']}")
            return entry['name'], file_hash
    return None, None

# Scan a directory for threats
def scan_directory(path, results_widget, progress_var, progress_label):
    threats_found = []
    total_files = sum([len(files) for _, _, files in os.walk(path)])  # Get total number of files to scan
    scanned_files = 0

    if os.path.isfile(path):  # If it's a file
        file_hash = hash_file(path)
        file_name, hash_found = check_threat(file_hash)
        if hash_found:
            threats_found.append((path, file_hash, file_name))
        scanned_files += 1
        update_progress(progress_var, scanned_files, total_files, results_widget, progress_label)

    elif os.path.isdir(path):  # If it's a directory
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = hash_file(file_path)
                file_name, hash_found = check_threat(file_hash)
                if hash_found:
                    threats_found.append((file_path, file_hash, file_name))
                scanned_files += 1
                update_progress(progress_var, scanned_files, total_files, results_widget, progress_label)

    return threats_found

def update_progress(progress_var, scanned_files, total_files, results_widget, progress_label):
    progress = (scanned_files / total_files) * 100 if total_files > 0 else 0
    progress_var.set(progress)
    progress_label.config(text=f"{int(progress)}%")
    results_widget.update_idletasks()

# GUI for the antivirus program
class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Kybero Antivirus")
        self.root.geometry("600x500")  # Increase the window size to accommodate logs
        
        # Add title
        self.title_label = ttk.Label(self.root, text="Kybero Antivirus", font=("Helvetica", 16))
        self.title_label.pack(pady=10)

        # Scan button
        self.scan_button = ttk.Button(self.root, text="Select File or Folder to Scan", command=self.select_file_or_folder, state=tk.DISABLED)
        self.scan_button.pack(pady=10)

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

        # Loading label
        self.loading_label = ttk.Label(self.root, text="Loading threat database...", font=("Helvetica", 12))
        self.loading_label.pack(pady=10)

        # Thread for loading database
        self.load_db_thread = threading.Thread(target=self.load_database, daemon=True)
        self.load_db_thread.start()

    def load_database(self):
        global threat_db
        threat_db = load_threat_db()

        # After loading, update the GUI
        self.root.after(0, self.database_loaded)

    def database_loaded(self):
        self.loading_label.config(text="Database loaded successfully!")
        self.scan_button.config(state=tk.NORMAL)  # Enable the scan button after loading

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
        threats = scan_directory(path, self.results_text, self.progress_var, self.percentage_label)
        self.display_results(threats)

    def display_results(self, threats):
        self.results_text.delete(1.0, tk.END)  # Clear existing text
        if threats:
            for threat in threats:
                # Display threat name along with file path and hash
                self.results_text.insert(tk.END, f"Threat detected: {threat[2]} in file {threat[0]} with hash {threat[1]}\n")
                self.ask_action_for_threat(threat)
        else:
            self.results_text.insert(tk.END, "No threats detected.\n")

    def ask_action_for_threat(self, threat):
        # Ask the user what to do with the threat (Delete, Quarantine, Ignore)
        action = tk.simpledialog.askstring("Threat Detected", f"Choose an action for {threat[2]}:\n\n(1) Delete\n(2) Quarantine\n(3) Ignore")

        if action == "1":
            self.delete_threat(threat[0])
        elif action == "2":
            self.quarantine_threat(threat[0])
        elif action == "3":
            self.ignore_threat(threat[0])
        else:
            messagebox.showerror("Invalid Action", "Invalid action. Please choose 1, 2, or 3.")

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
        self.root.geometry("400x200")
        
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
        main_window = AntivirusGUI(main_root)
        main_root.mainloop()


if __name__ == "__main__":
    # Create the welcome window
    root = tk.Tk()
    welcome_window = WelcomeWindow(root)
    root.mainloop()
