TriageX
Real-time anomaly detection and prioritization tool for cybersecurity triage

Overview
TriageX is a real-time forensic and cybersecurity triage tool that detects, analyzes, and prioritizes system and network anomalies. Built using machine learning, it empowers users to respond quickly to threats, enhancing digital safety in an accessible and ethical manner.

Features
Network Monitoring: Tracks bytes sent/received, connections, and packet loss.

System Monitoring: Monitors CPU, memory, disk usage, and running processes.

File Scanning: Detects suspicious files using extension and name patterns.

Anomaly Detection: Uses Isolation Forest to detect real-time outliers.

Triage Prioritization: Random Forest model classifies anomalies into Low/Medium/High priority.

Interactive UI: Tkinter interface with clickable logs and visual reports (heatmaps, confusion matrix).

Installation
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/triagex.git
cd triagex
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
(Optional) Download and preprocess the NSL-KDD dataset:

Save processed file as external_training_data.csv in the project folder.

Usage
Run the tool:

bash
Copy
Edit
python triagex.py
Use the UI tabs to monitor, scan, and triage.

Logs are saved automatically.

Reports are saved as images (e.g., external_rf_confusion_matrix.png).

Technology Stack
Python Libraries: Tkinter, Scikit-learn, Psutil, Pandas, Seaborn, Matplotlib

Models Used: Isolation Forest, Random Forest Classifier

Dataset: NSL-KDD for training priority model

Contributing
Feel free to fork and contribute via pull requests. Suggestions and improvements are welcome, especially around real-world dataset integration and UI features.
