# Intelligent-Log-Anomaly-Detection

This project implements a secure and automated malware detection pipeline that encrypts Hadoop log data, stores it securely in an SQLite database, and uses machine learning models to classify logs as benign or malicious. If malicious, it further identifies the specific malware type using a secondary classifier.

🧠 Features

Automatic Log Encryption
Encrypts all Hadoop log files using AES-based symmetric encryption (cryptography.Fernet) before storing them in a local SQLite database.

Dynamic Model Loading
Automatically loads the latest or feature-matched versions of the binary and malware classification models.

Secure Storage
Encrypted logs are stored in secure_logs.db instead of plaintext, protecting sensitive data.

Malware Inference Pipeline

Step 1: Binary classification (Benign / Malicious)

Step 2: Malware type classification (e.g., Trojan, Worm, Ransomware, etc.)

Randomized Inference
Randomly selects Hadoop and AWS logs for model testing to simulate real-world streaming data behavior.

📁 Project Structure
Specilisation_project/
│
├── Hadoop_log/                     # Hadoop log files (*.log)
├── Binary_classfication_model/     # Pre-trained binary models (*.pkl)
├── Malware_classifcation_model/    # Pre-trained malware models (*.pkl)
├── a_600_all_malware_combined.csv  # Reference dataset (optional, for label decoding)
│
├── secure_logs.db                  # SQLite database (auto-created)
├── hadoop_key.key                  # Encryption key (auto-generated)
│
├── secure_malware_pipeline.py      # Main Python script (this code)
└── README.md                       # Documentation

⚙️ Requirements

Install dependencies using:

pip install pandas joblib cryptography xgboost


Note: xgboost warnings are suppressed to avoid clutter.

🚀 How to Run
1. Prepare the directories

Ensure that the following folders exist and contain data:

Hadoop_log/ → raw Hadoop logs (.log files)

Binary_classfication_model/ → binary classification models

Malware_classifcation_model/ → malware classification models

2. Run the main script
python secure_malware_pipeline.py

3. Pipeline flow

Encrypt Hadoop logs

Searches recursively in Hadoop_log/

Encrypts each .log file using a Fernet key

Stores encrypted blobs in secure_logs.db

Run inference

Randomly selects one Hadoop log and one AWS dataset file

Encrypts and stores Hadoop log lines

Runs binary classification model

If malicious → runs malware classification model

Displays malware type prediction
