import tkinter as tk
from tkinter import filedialog, messagebox
import logging
import multiprocessing
import math
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import pandas as pd
import os
import json
import csv
from datetime import datetime
import json
from fpdf import FPDF  # PDF library


# Set up logging
logging.basicConfig(filename='triage.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Forensic Triage Functions
def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            entropy = calculate_entropy_helper(data)
        return entropy
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

def calculate_entropy_helper(data):
    if len(data) == 0:
        return 0
    entropy = 0
    byte_counts = {byte: data.count(byte) for byte in set(data)}
    total_bytes = len(data)
    for byte, count in byte_counts.items():
        prob = count / total_bytes
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy

def analyze_metadata(file_path):
    metadata = {}
    try:
        metadata["size"] = os.path.getsize(file_path)
        metadata["type"] = os.path.splitext(file_path)[1]
        metadata["created"] = datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
        metadata["modified"] = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        metadata["accessed"] = datetime.fromtimestamp(os.path.getatime(file_path)).isoformat()
    except Exception as e:
        logging.error(f"Error analyzing metadata for {file_path}: {e}")
    return metadata

def analyze_file_structure(file_path):
    file_structure = {}
    try:
        with open(file_path, "rb") as file:
            data = file.read(1024)  # Read first 1KB for structure analysis
            file_structure["header"] = data[:4]  # Example: Read first 4 bytes as header
            file_structure["footer"] = data[-4:]  # Example: Read last 4 bytes as footer
    except Exception as e:
        logging.error(f"Error analyzing file structure for {file_path}: {e}")
    return file_structure

def detect_metadata_anomalies(metadata):
    anomalies = []
    if metadata["size"] > 1000000:  # Example: Files larger than 1MB
        anomalies.append("Large file size")
    if metadata["type"] not in [".doc", ".pdf", ".xls"]:  # Example: Unexpected file type
        anomalies.append("Unexpected file type")
    return anomalies

def detect_file_structure_anomalies(file_structure):
    anomalies = []
    if file_structure["header"] != b'\x50\x4B\x03\x04':  # Example: Check for ZIP file header
        anomalies.append("Unexpected file header")
    return anomalies

def detect_entropy_anomalies(entropy):
    anomalies = []
    if entropy is not None and entropy > 7.0:  # Example: High entropy threshold
        anomalies.append("High entropy")
    return anomalies

def detect_hidden_files(file_path):
    return [file_path] if file_path.startswith('.') else []

def triage_file(file_path):
    result = {}
    result["file"] = file_path
    result["entropy"] = calculate_entropy(file_path)
    if result["entropy"] is not None:
        result["metadata"] = analyze_metadata(file_path)
        result["file_structure"] = analyze_file_structure(file_path)
        result["metadata_anomalies"] = detect_metadata_anomalies(result["metadata"])
        result["file_structure_anomalies"] = detect_file_structure_anomalies(result["file_structure"])
        result["entropy_anomalies"] = detect_entropy_anomalies(result["entropy"])
        result["hidden_files"] = detect_hidden_files(file_path)
    return result

def triage_directory(directory_path):
    results = []
    for root, dirs, files in os.walk(directory_path):
        file_paths = [os.path.join(root, file) for file in files]
        with multiprocessing.Pool() as pool:
            results.extend(pool.map(triage_file, file_paths))
    return results

def train_anomaly_detection_model(df):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[['size', 'entropy']].fillna(0))
    model = IsolationForest(contamination=0.1)
    model.fit(X_scaled)
    return model, scaler

def detect_anomalies_with_model(df, model, scaler):
    X_scaled = scaler.transform(df[['size', 'entropy']].fillna(0))
    df['anomaly_score'] = model.decision_function(X_scaled)
    df['anomaly_status'] = df['anomaly_score'].apply(lambda x: 'Anomaly Detected' if x < 0 else 'Normal')
    return df

def save_to_csv(df, file_path):
    try:
        df.to_csv(file_path, index=False)
    except Exception as e:
        logging.error(f"Error saving CSV file: {e}")
        messagebox.showerror("Error", f"Error saving CSV file: {e}")




def save_to_json(df, file_path):
    try:
        # Convert DataFrame to JSON-serializable format
        df = df.copy()  # Create a copy to avoid modifying the original DataFrame

        # Ensure all data types are JSON serializable
        for column in df.columns:
            if df[column].dtype == 'object':
                df[column] = df[column].astype(str)

        # Specify date format if known; example formats: '%Y-%m-%d %H:%M:%S' or '%d/%m/%Y'
        date_format = '%Y-%m-%d %H:%M:%S'  # Adjust this format to match your data

        # Convert columns to datetime, handling errors explicitly
        for column in df.columns:
            if df[column].dtype == 'object':
                try:
                    df[column] = pd.to_datetime(df[column], format=date_format, errors='coerce')  # Use 'coerce' to handle errors
                except Exception as e:
                    logging.warning(f"Could not convert column '{column}' to datetime: {e}")

        # Convert DataFrame to JSON format
        json_data = df.to_json(orient="records", lines=True, force_ascii=False)
        
        # Save JSON data to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(json_data)
        
        logging.info(f"JSON file saved successfully at {file_path}")
    except Exception as e:
        logging.error(f"Error saving JSON file: {e}")
        messagebox.showerror("Error", f"Error saving JSON file: {e}")


def save_to_pdf(df, file_path):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        for i, row in df.iterrows():
            for col in df.columns:
                pdf.cell(200, 10, txt=f"{col}: {row[col]}", ln=True)
            pdf.ln(10)
        
        pdf.output(file_path)
    except Exception as e:
        logging.error(f"Error saving PDF file: {e}")
        messagebox.showerror("Error", f"Error saving PDF file: {e}")

def automate_triage(directory_path, formats):
    try:
        triage_results = triage_directory(directory_path)
        df = pd.DataFrame(triage_results)

        # Debugging: Print the DataFrame columns and the first few rows
        logging.info(f"DataFrame columns: {df.columns.tolist()}")
        logging.info(f"DataFrame preview:\n{df.head()}")

        # Extract 'size' from 'metadata' and add it as a separate column
        if 'metadata' in df.columns:
            metadata_df = df['metadata'].apply(pd.Series)
            df = pd.concat([df.drop(columns=['metadata']), metadata_df], axis=1)
        
        # Ensure 'size' and 'entropy' columns are present
        if 'size' not in df.columns or 'entropy' not in df.columns:
            raise ValueError("Required columns are missing from the DataFrame.")
        
        # Train and apply anomaly detection model
        if not df.empty:
            model, scaler = train_anomaly_detection_model(df)
            df = detect_anomalies_with_model(df, model, scaler)

            # Save the DataFrame based on user selections
            if 'csv' in formats:
                save_to_csv(df, "triage_results_with_model.csv")
            if 'json' in formats:
                save_to_json(df, "triage_results_with_model.json")
            if 'pdf' in formats:
                save_to_pdf(df, "triage_results_with_model.pdf")
        else:
            logging.info("No files to process.")
    except Exception as e:
        logging.error(f"Error during triage process: {e}")

# Tkinter GUI
class ForensicTriageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Triage Tool")
        self.create_widgets()
        self.directory_path = None
        self.formats = []

    def create_widgets(self):
        # Title label
        self.title_label = tk.Label(self.root, text="Forensic Triage Tool", font=("Helvetica", 16))
        self.title_label.pack(pady=10)

        # Directory selection
        self.directory_frame = tk.Frame(self.root)
        self.directory_frame.pack(pady=10, padx=10, fill=tk.X)

        self.directory_label = tk.Label(self.directory_frame, text="Select Directory:")
        self.directory_label.pack(side=tk.LEFT, padx=5)

        self.directory_entry = tk.Entry(self.directory_frame, width=50, state=tk.DISABLED)
        self.directory_entry.pack(side=tk.LEFT, padx=5)

        self.browse_button = tk.Button(self.directory_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        # Format selection
        self.format_frame = tk.Frame(self.root)
        self.format_frame.pack(pady=10, padx=10, fill=tk.X)

        self.csv_var = tk.BooleanVar()
        self.json_var = tk.BooleanVar()
        self.pdf_var = tk.BooleanVar()

        self.csv_check = tk.Checkbutton(self.format_frame, text="CSV", variable=self.csv_var)
        self.csv_check.pack(side=tk.LEFT, padx=5)

        self.json_check = tk.Checkbutton(self.format_frame, text="JSON", variable=self.json_var)
        self.json_check.pack(side=tk.LEFT, padx=5)

        self.pdf_check = tk.Checkbutton(self.format_frame, text="PDF", variable=self.pdf_var)
        self.pdf_check.pack(side=tk.LEFT, padx=5)

        # Start triage button
        self.start_button = tk.Button(self.root, text="Start Triage", command=self.start_triage)
        self.start_button.pack(pady=20)

        # Status label
        self.status_label = tk.Label(self.root, text="", font=("Helvetica", 12))
        self.status_label.pack(pady=10)

    def browse_directory(self):
        self.directory_path = filedialog.askdirectory()
        if self.directory_path:
            self.directory_entry.config(state=tk.NORMAL)
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, self.directory_path)
            self.directory_entry.config(state=tk.DISABLED)
            self.status_label.config(text="Directory selected.")

    def start_triage(self):
        if self.directory_path:
            self.formats = []
            if self.csv_var.get():
                self.formats.append('csv')
            if self.json_var.get():
                self.formats.append('json')
            if self.pdf_var.get():
                self.formats.append('pdf')
            
            if not self.formats:
                messagebox.showwarning("Warning", "No output format selected.")
                return

            try:
                self.status_label.config(text="Processing...")
                self.root.update_idletasks()
                automate_triage(self.directory_path, self.formats)
                self.status_label.config(text="Triage completed successfully.")
            except Exception as e:
                logging.error(f"An error occurred: {e}")
                messagebox.showerror("Error", f"An error occurred: {e}")
                self.status_label.config(text="Triage failed.")
        else:
            messagebox.showwarning("Warning", "No directory selected.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicTriageApp(root)
    root.mainloop()
