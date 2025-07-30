# TriageX - Real-Time Anomaly Detection Tool

TriageX is a real-time forensic tool designed to analyze system and network behavior for suspicious activity and anomalies. It provides live monitoring, file scanning, anomaly detection using machine learning models, and easy-to-read reports — all through a user-friendly desktop GUI built with Python’s Tkinter.

---

## 📌 Key Features

- **🔴 Real-Time System Monitoring**
  - CPU, Memory, Disk, and Process tracking
- **🌐 Network Activity Tracking**
  - Monitor IP, bytes sent/received, active connections, simulated packet loss
- **🦠 Suspicious File Scanner**
  - Scans drives (`C:/`, `D:/`) for known malicious file types and names
- **🧠 Machine Learning-Based Anomaly Detection**
  - Uses `Isolation Forest` and `Random Forest Classifier` to label activity as Low/Medium/High risk
- **📊 Visual Reports**
  - Correlation heatmaps and CSV logs of anomalies and suspicious files
- **📁 NSL-KDD Dataset Integration**
  - Leverages real-world intrusion detection data for training

---

## 💡 How It Works

1. **Live Monitoring:** Tracks system and network metrics in real time.
2. **File Scan:** Searches for potentially malicious files based on name and extension.
3. **Anomaly Detection:** Trains Random Forest on the NSL-KDD dataset. Uses Isolation Forest for unsupervised anomaly detection.
4. **Triage Dashboard:** Shows labeled priority of threats and anomalies.
5. **Reporting:** Saves analysis results and visualizations for review.

---

## 🧠 Dataset Used

This project uses the NSL-KDD dataset for ML training:

- **Source:** [Kaggle: NSL-KDD Intrusion Detection System](https://www.kaggle.com/code/eneskosar19/intrusion-detection-system-nsl-kdd)
- **Preprocessing:** Selected features from the dataset are used and assigned random priority labels for triage model training.

---

## 🛠️ Installation & Setup

### ✅ Requirements

- Python 3.8+
- Recommended to run on Windows (for file scanning)

### 🔧 Install Dependencies

```bash
pip install pandas numpy matplotlib seaborn scikit-learn psutil
```

### 🚀 Run the App

```bash
python triagex.py
```

---

## 👨‍💻 Author

Developed by **scriptkidder, Arcy-me**  
