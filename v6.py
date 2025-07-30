# TriageX - Real-Time Anomaly Detection Tool (Enhanced)
# Author: [Your Name]
# Description: Real-time forensic tool analyzing network and system data for anomalies

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import threading
import logging
import os
import psutil
import socket
import time
import hashlib
import glob


# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Suspicious file extensions and names for scanning
SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.bat', '.scr', '.ps1']
SUSPICIOUS_NAMES = ['keylogger', 'trojan', 'malware', 'ransom']

# Descriptions for technical terms
LOG_DESCRIPTIONS = {
    'cpu': 'CPU Usage (%) - Indicates the current percentage of CPU utilization.',
    'memory': 'Memory Usage (%) - Indicates how much RAM is being used.',
    'disk': 'Disk Usage (%) - Indicates how much disk space is in use.',
    'processes': 'Number of Running Processes - Total number of processes running on the system.',
    'bytes_sent': 'Bytes Sent - Amount of data sent over the network.',
    'bytes_recv': 'Bytes Received - Amount of data received over the network.',
    'connections': 'Active Connections - Number of open network connections.',
    'packet_loss': 'Packet Loss - Indicates potential network issues or data loss.',
    'anomaly': 'Anomaly - Indicates if this entry is considered anomalous.',
    'priority': 'Priority Level - Indicates urgency (Low, Medium, High).'
}

# External Random Forest Model Loader (add-on, no changes to existing code)
def load_external_random_forest():
    try:
        external_data = pd.read_csv("external_training_data.csv")  # External labeled dataset
        X_ext = external_data.drop(columns=['priority'])
        y_ext = external_data['priority'].map({'Low': 0, 'Medium': 1, 'High': 2})
        rf_global = RandomForestClassifier(n_estimators=300, max_depth=None, random_state=42)
        rf_global.fit(X_ext, y_ext)
        logging.info("External Random Forest model trained successfully.")

        # Accuracy evaluation
        X_train, X_test, y_train, y_test = train_test_split(X_ext, y_ext, test_size=0.2, random_state=42)
        rf_eval = RandomForestClassifier(n_estimators=300, max_depth=None, random_state=42)
        rf_eval.fit(X_train, y_train)
        y_pred = rf_eval.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        logging.info(f"External RF Model Accuracy: {acc:.2f}")

        # Save confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Low', 'Medium', 'High'], yticklabels=['Low', 'Medium', 'High'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('External RF Confusion Matrix')
        plt.savefig("external_rf_confusion_matrix.png")
        plt.close()

        return rf_global
    except Exception as e:
        logging.warning(f"External dataset not loaded or failed to train RF: {e}")
        return None

rf_global_model = load_external_random_forest()

# Dataset Preprocessor for NSL-KDD (add-on)
def preprocess_nsl_kdd_dataset():
    try:
        dataset_path = "C:\\Users\\joshi\\OneDrive\\Desktop\\new tirage\\external_training_data.csv"
        if not os.path.exists(dataset_path):
            logging.error(f"Dataset file not found: {dataset_path}")
            return
        df = pd.read_csv(dataset_path)  # Load the dataset
        selected_columns = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent']
        df_selected = df[selected_columns]
        if 'priority' not in df_selected.columns:
            df_selected['priority'] = np.random.choice(['Low', 'Medium', 'High'], size=len(df_selected))
        df_selected.to_csv("C://Users//joshi//OneDrive//Desktop//new tirage//external_training_data.csv", index=False)
        logging.info("Preprocessed NSL-KDD dataset saved as external_training_data.csv")
    except Exception as e:
        logging.error(f"Failed to preprocess NSL-KDD dataset: {e}")



# UI Class
class TriageXApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TriageX - Real-Time Anomaly Detection")
        self.root.geometry("1000x700")
        self.create_widgets()
        self.network_data = pd.DataFrame()
        self.system_data = pd.DataFrame()
        self.suspicious_files = []
        self.triage_results = pd.DataFrame()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.root)

        self.network_tab = ttk.Frame(self.tab_control)
        self.system_tab = ttk.Frame(self.tab_control)
        self.report_tab = ttk.Frame(self.tab_control)
        self.triage_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.network_tab, text='Network Monitor')
        self.tab_control.add(self.system_tab, text='System Monitor')
        self.tab_control.add(self.report_tab, text='Reports & Graphs')
        self.tab_control.add(self.triage_tab, text='Triage')
        self.tab_control.pack(expand=1, fill='both')

        self.create_network_tab()
        self.create_system_tab()
        self.create_report_tab()
        self.create_triage_tab()

    def create_network_tab(self):
        ttk.Label(self.network_tab, text="Real-Time Network Monitoring", font=("Arial", 14)).pack(pady=10)
        ttk.Button(self.network_tab, text="Start Monitoring", command=self.start_network_monitor).pack(pady=5)
        self.network_text = tk.Text(self.network_tab, height=25)
        self.network_text.pack(expand=1, fill='both')
        self.network_text.bind("<Double-Button-1>", self.show_log_description)

    def create_system_tab(self):
        ttk.Label(self.system_tab, text="Real-Time System Monitoring", font=("Arial", 14)).pack(pady=10)
        ttk.Button(self.system_tab, text="Start Monitoring", command=self.start_system_monitor).pack(pady=5)
        ttk.Button(self.system_tab, text="Scan Memory for Suspicious Files", command=self.scan_suspicious_files).pack(pady=5)
        self.system_text = tk.Text(self.system_tab, height=25)
        self.system_text.pack(expand=1, fill='both')
        self.system_text.bind("<Double-Button-1>", self.show_log_description)

    def create_report_tab(self):
        ttk.Label(self.report_tab, text="Reports", font=("Arial", 14)).pack(pady=10)
        ttk.Button(self.report_tab, text="Run Triage Analysis", command=self.run_triage_analysis).pack(pady=5)
        ttk.Button(self.report_tab, text="Generate Report", command=self.generate_report).pack(pady=5)
        self.report_text = tk.Text(self.report_tab, height=25)
        self.report_text.pack(expand=1, fill='both')
        self.report_text.bind("<Double-Button-1>", self.show_log_description)

    def create_triage_tab(self):
        ttk.Label(self.triage_tab, text="Triage Dashboard", font=("Arial", 14)).pack(pady=10)
        ttk.Button(self.triage_tab, text="Start Triage", command=self.run_triage_analysis).pack(pady=5)
        self.triage_text = tk.Text(self.triage_tab, height=25)
        self.triage_text.pack(expand=1, fill='both')
        self.triage_text.bind("<Double-Button-1>", self.show_log_description)

    def show_log_description(self, event):
        widget = event.widget
        try:
            index = widget.index("@%s,%s linestart" % (event.x, event.y))
            line = widget.get(index, f"{index} lineend").lower()
            matched = False
            for key, description in LOG_DESCRIPTIONS.items():
                if key in line:
                    messagebox.showinfo("Log Detail", f"{key.upper()}\n\n{description}")
                    matched = True
                    break
            if not matched:
                messagebox.showinfo("Log Detail", "No technical description available for this log line.")
        except Exception as e:
            logging.error(f"Error showing log description: {e}")


    def start_network_monitor(self):
        threading.Thread(target=self.monitor_network, daemon=True).start()

    def start_system_monitor(self):
        threading.Thread(target=self.monitor_system, daemon=True).start()

    def monitor_network(self):
        self.network_text.delete('1.0', tk.END)
        logging.info("Monitoring network...")
        for _ in range(50):
            try:
                ip = socket.gethostbyname(socket.gethostname())
                sent = psutil.net_io_counters().bytes_sent
                recv = psutil.net_io_counters().bytes_recv
                connections = len(psutil.net_connections())
                packet_loss = np.random.rand()

                entry = {
                    'ip': ip,
                    'bytes_sent': sent,
                    'bytes_recv': recv,
                    'connections': connections,
                    'packet_loss': packet_loss
                }
                self.network_data = pd.concat([self.network_data, pd.DataFrame([entry])], ignore_index=True)
                self.network_text.insert(tk.END, f"{entry}\n")
                time.sleep(1)
            except Exception as e:
                logging.error(f"Network monitor error: {e}")

    def monitor_system(self):
        self.system_text.delete('1.0', tk.END)
        logging.info("Monitoring system...")
        for _ in range(50):
            try:
                cpu = psutil.cpu_percent()
                memory = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent
                processes = len(psutil.pids())

                entry = {
                    'cpu': cpu,
                    'memory': memory,
                    'disk': disk,
                    'processes': processes
                }
                self.system_data = pd.concat([self.system_data, pd.DataFrame([entry])], ignore_index=True)
                self.system_text.insert(tk.END, f"{entry}\n")
                time.sleep(1)
            except Exception as e:
                logging.error(f"System monitor error: {e}")

    def scan_suspicious_files(self):
        self.system_text.insert(tk.END, "\nScanning memory and system for suspicious files...\n")
        found_files = []
        try:
            for root_dir in ['C:/', 'D:/']:
                for dirpath, dirnames, filenames in os.walk(root_dir):
                    for file in filenames:
                        file_lower = file.lower()
                        file_ext = os.path.splitext(file_lower)[1]
                        if file_ext in SUSPICIOUS_EXTENSIONS:
                            for name in SUSPICIOUS_NAMES:
                                if name in file_lower:
                                    filepath = os.path.join(dirpath, file)
                                    hash_val = self.hash_file(filepath)
                                    found_files.append({'file': filepath, 'hash': hash_val})
                                    self.system_text.insert(tk.END, f"Suspicious File Found: {filepath} Hash: {hash_val}\n")
        except Exception as e:
            logging.error(f"File scan error: {e}")

        self.suspicious_files = found_files
        if not found_files:
            self.system_text.insert(tk.END, "No suspicious files found.\n")

    def hash_file(self, filepath):
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Hashing error for {filepath}: {e}")
            return "Error"

    def run_triage_analysis(self):
        logging.info("Running triage analysis...")
        try:
            combined_df = pd.concat([self.network_data.drop(columns=['ip']), self.system_data], axis=1).dropna()
            combined_df['triage_score'] = combined_df.mean(axis=1)
            combined_df['priority'] = pd.qcut(combined_df['triage_score'], q=3, labels=['Low', 'Medium', 'High'])

            iso = IsolationForest(contamination=0.1, random_state=42)
            combined_df['anomaly_score'] = iso.fit_predict(combined_df.drop(columns=['triage_score', 'priority']))
            combined_df['anomaly'] = combined_df['anomaly_score'].apply(lambda x: 'Yes' if x == -1 else 'No')

            X = combined_df.drop(columns=['triage_score', 'priority', 'anomaly_score', 'anomaly'])
            y = combined_df['priority'].map({'Low': 0, 'Medium': 1, 'High': 2})
            rf = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42)
            rf.fit(X, y)
            combined_df['rf_priority'] = rf.predict(X)
            combined_df['rf_priority'] = combined_df['rf_priority'].map({0: 'Low', 1: 'Medium', 2: 'High'})

            self.triage_results = combined_df

            self.report_text.delete('1.0', tk.END)
            self.report_text.insert(tk.END, self.triage_results.head(20).to_string())
            self.report_text.insert(tk.END, "\nTriage analysis complete.\n")

            self.triage_text.delete('1.0', tk.END)
            self.triage_text.insert(tk.END, self.triage_results.head(20).to_string())
            self.triage_text.insert(tk.END, "\nTriage analysis complete.\n")

        except Exception as e:
            self.report_text.insert(tk.END, f"Error in triage analysis: {e}\n")
            self.triage_text.insert(tk.END, f"Error in triage analysis: {e}\n")

    def generate_report(self):
        logging.info("Generating anomaly report...")
        try:
            sns.heatmap(self.system_data.corr(), annot=True)
            plt.title("System Data Correlation")
            plt.savefig("system_correlation.png")
            plt.close()

            if not self.triage_results.empty:
                self.triage_results.to_csv("triage_report.csv", index=False)
                self.report_text.insert(tk.END, "Triage report saved to triage_report.csv\n")

            if self.suspicious_files:
                suspicious_df = pd.DataFrame(self.suspicious_files)
                suspicious_df.to_csv("suspicious_files.csv", index=False)
                self.report_text.insert(tk.END, "Suspicious files saved to suspicious_files.csv\n")

        except Exception as e:
            self.report_text.insert(tk.END, f"Error generating report: {e}\n")

# Run App
preprocess_nsl_kdd_dataset()  # Preprocess the NSL-KDD dataset
if __name__ == '__main__':
    root = tk.Tk()
    app = TriageXApp(root)
    root.mainloop()

