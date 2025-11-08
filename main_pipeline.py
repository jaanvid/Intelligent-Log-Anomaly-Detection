import os
import re
import random
import sqlite3
import pandas as pd
import joblib
from pathlib import Path
from cryptography.fernet import Fernet
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")

# ============================
# CONFIGURATION
# ============================

BASE_DIR = Path("/Users/beta/Downloads/Specilisation_project")
HADOOP_LOG_DIR = BASE_DIR / "Hadoop_log"
AWS_DIR = BASE_DIR / "AWSCTD_log"
BINARY_MODELS_DIR = BASE_DIR / "Binary_classfication_model"
MALWARE_MODELS_DIR = BASE_DIR / "Malware_classifcation_model"
DB_PATH = BASE_DIR / "secure_logs.db"

DB_PATH = BASE_DIR / "secure_logs.db"
ENCRYPTION_KEY_FILE = BASE_DIR / "hadoop_key.key"

# ============================
# DATABASE & ENCRYPTION
# ============================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_hadoop_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            encrypted_data BLOB
        )
    """)
    conn.commit()
    conn.close()


def get_encryption_key():
    if ENCRYPTION_KEY_FILE.exists():
        return ENCRYPTION_KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        ENCRYPTION_KEY_FILE.write_bytes(key)
        return key


def encrypt_and_store_hadoop_logs(hadoop_dir: Path):
    """Encrypt all Hadoop logs and store in SQLite DB."""
    key = get_encryption_key()
    cipher = Fernet(key)

    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    log_files = list(hadoop_dir.rglob("*.log"))
    if not log_files:
        print("⚠️ No Hadoop log files found.")
        return

    for log_file in log_files:
        with open(log_file, "rb") as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        cursor.execute(
            "INSERT INTO encrypted_hadoop_logs (filename, encrypted_data) VALUES (?, ?)",
            (log_file.name, encrypted_data)
        )
    conn.commit()
    conn.close()
    print(f"✅ Encrypted and stored {len(log_files)} Hadoop log file(s) in {DB_PATH.name}\n")


# ============================
# MODEL LOADING
# ============================

def load_model(task: str, version: str = None, feature_count: int = None):
    if task == "binary":
        models_dir = BINARY_MODELS_DIR
        pattern = r"(\d+)_binary_classification_random_forest_model\.pkl"
    elif task == "malware":
        models_dir = MALWARE_MODELS_DIR
        pattern = r"(\d+)_malware_classification_model(?:_|)\.pkl"
    else:
        raise ValueError("task must be 'binary' or 'malware'")

    model_files = list(models_dir.glob("*.pkl"))
    if not model_files:
        raise FileNotFoundError(f"No model files found in {models_dir}")

    # Match by feature count if provided
    if feature_count is not None:
        for file in model_files:
            match = re.search(pattern, file.name)
            if match and int(match.group(1)) == feature_count:
                model_path = file
                version_num = int(match.group(1))
                break
        else:
            print(f"⚠️ No model found for {feature_count} features; using latest instead.")
            versions = [(int(re.search(pattern, f.name).group(1)), f) for f in model_files if re.search(pattern, f.name)]
            version_num, model_path = max(versions, key=lambda x: x[0])
    else:
        versions = [(int(re.search(pattern, f.name).group(1)), f) for f in model_files if re.search(pattern, f.name)]
        version_num, model_path = max(versions, key=lambda x: x[0])

    model = joblib.load(model_path)
    print(f"✅ Loaded {task} model: {model_path.name}")
    return model, model_path.name, version_num


# ============================
# INFERENCE
# ============================

# -------------------------------------------------------------------
# Helper: Random file selection from nested folders
# -------------------------------------------------------------------
def get_random_file(base_dir: Path):
    """Recursively pick a random file from a directory (including subfolders)."""
    all_files = [p for p in base_dir.rglob("*") if p.is_file()]
    if not all_files:
        print(f"⚠️ No files found in {base_dir}")
        return None
    chosen_file = random.choice(all_files)
    print(f"🎲 Randomly selected: {chosen_file}")
    return chosen_file


# -------------------------------------------------------------------
# Helper: Encrypt and store Hadoop logs into SQLite database
# -------------------------------------------------------------------
def store_encrypted_logs(hadoop_lines, db_path):
    """Encrypts Hadoop log lines and stores them securely in an SQLite DB."""
    # Generate encryption key (you can load this from a file later if you want)
    key_file = Path("encryption.key")
    if key_file.exists():
        key = key_file.read_bytes()
    else:
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        print("🔑 Generated new encryption key and saved it to 'encryption.key'")

    fernet = Fernet(key)

    # Connect to SQLite database (creates it if missing)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create table if it doesn’t exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_content TEXT NOT NULL
        )
    """)

    # Encrypt each line and store
    for line in hadoop_lines:
        encrypted = fernet.encrypt(line.encode("utf-8"))
        c.execute("INSERT INTO encrypted_logs (encrypted_content) VALUES (?)", (encrypted.decode("utf-8"),))

    conn.commit()
    conn.close()
    print(f"🧱 Stored {len(hadoop_lines)} encrypted Hadoop log entries in database.")


def run_model_inference():
    print("⚙️ Running model inference...\n")

    # --- RANDOM FILE SELECTION ---
    hadoop_file = get_random_file(HADOOP_LOG_DIR)
    aws_file = get_random_file(AWS_DIR)

    print(f"\n📄 Using Hadoop log: {hadoop_file.name}")

    # --- Load Hadoop log and store encrypted ---
    with open(hadoop_file, "r", errors="ignore") as f:
        hadoop_lines = f.readlines()
    store_encrypted_logs(hadoop_lines, DB_PATH)  # only store Hadoop logs
    print(f"✅ Encrypted and stored {len(hadoop_lines)} Hadoop log lines.\n")

    # --- Load AWS dataset dynamically ---
    df = pd.read_csv(aws_file, header=None)
    print(f"📘 Loaded HADOOP dataset '{aws_file.name}' with {df.shape[0]} samples and {df.shape[1]-1} features.\n")

    # Split features and labels
    X = df.iloc[:, :-1]
    y = df.iloc[:, -1]

    # Pick one random sample
    i = random.randint(0, len(X) - 1)
    sample = X.iloc[i:i+1]
    label = y.iloc[i]

    print(f"Expected label: {label}\n")

    # --- Binary Classification: Malware or Not ---
    binary_model, _, bin_version = load_model("binary", feature_count=X.shape[1])
    binary_pred = binary_model.predict(sample)[0]

    if binary_pred == 0:
        print("🟢 Prediction: This log is BENIGN.\n")
        return
    else:
        print("🔴 Prediction: This log is MALICIOUS.")
        print("⏳ Identifying malware type...\n")

    # --- Malware Classification: Which Malware ---
    malware_model, _, mal_version = load_model("malware", feature_count=X.shape[1])
    malware_pred_code = malware_model.predict(sample)[0]

    # --- Decode Malware Label from Original Combined Dataset ---
    malware_labels_path = BASE_DIR / "a_600_all_malware_combined.csv"
    if malware_labels_path.exists():
        df_labels = pd.read_csv(malware_labels_path, header=None)

        # Find label column (the one that isn’t numeric)
        label_col = None
        for col in df_labels.columns:
            if not pd.to_numeric(df_labels[col], errors='coerce').notna().all():
                label_col = col
                break

        if label_col is not None:
            label_names = df_labels[label_col].astype('category').cat.categories.tolist()
            if 0 <= malware_pred_code < len(label_names):
                malware_pred_label = label_names[malware_pred_code]
            else:
                malware_pred_label = f"Unknown (code {malware_pred_code})"
        else:
            malware_pred_label = f"Unknown (code {malware_pred_code})"
    else:
        malware_pred_label = f"Unknown (code {malware_pred_code})"

    print(f"🧬 Predicted Malware Type: {malware_pred_label}\n")
    print("✅ Inference complete.")



# ============================
# MAIN ENTRY POINT
# ============================

if __name__ == "__main__":
    print("🚀 Starting Secure Malware Classification Pipeline...\n")

    # Step 1. Encrypt and store Hadoop logs only
    encrypt_and_store_hadoop_logs(HADOOP_LOG_DIR)

    # Step 2. Run inference on hadooop dataset (random sample)
    run_model_inference()
