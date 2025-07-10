import re
from datetime import datetime
from collections import defaultdict
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_curve, auc
from scipy.sparse import hstack
import json
import copy
import joblib  # for saving model

# === LOAD METADATA ===
try:
    with open("malicious_ips.json", "r") as f:
        metadata = json.load(f)
    malicious_ips = metadata.get("malicious_ips", [])
except FileNotFoundError:
    print("malicious_ips.json not found, using empty list")
    malicious_ips = []

trusted_users = ['root', 'admin', 'user', 'test', 'guest', 'devops', 'john_doe', 'oracle']

# === REGEX FOR LOG LINE PARSING ===
log_pattern = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) '
    r'\S+ sshd\[(?P<pid>\d+)\]: '
    r'(?P<status>\w+) password for (?P<user>\w*) from (?P<ip>[\d.]+) port \d+ ssh2'
)

def normalize_status(status):
    status = status.lower()
    if 'fail' in status:
        return 'Failed'
    elif 'accept' in status:
        return 'Accepted'
    else:
        return 'Unknown'

# === PARSE LOG FILE ===
logs = []
with open("simulated_auth.log", "r") as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            log = match.groupdict()
            log['status'] = normalize_status(log['status'])
            try:
                log['timestamp'] = datetime.strptime(log['timestamp'], "%b %d %H:%M:%S")
            except ValueError:
                continue
            logs.append(log)

df = pd.DataFrame(logs)

# === FEATURE ENGINEERING ===
df['hour'] = df['timestamp'].dt.hour
df['is_internal_ip'] = df['ip'].str.startswith("192.168.").astype(int)
df['is_malicious_ip'] = df['ip'].isin(malicious_ips).astype(int)
trusted_users_map = {u: i for i, u in enumerate(trusted_users)}
df['user_encoded'] = df['user'].apply(lambda x: trusted_users_map.get(x, -1))
df['status_failed'] = df['status'].apply(lambda s: 1 if s == 'Failed' else 0)

# Time-based features
df = df.sort_values(by='timestamp')
last_seen = {}
recent_fails = defaultdict(list)
time_deltas = []
failed_attempts = []

for idx, row in df.iterrows():
    ip = row['ip']
    now = row['timestamp']

    last_time = last_seen.get(ip)
    delta = (now - last_time).total_seconds() if last_time else -1
    time_deltas.append(delta)
    last_seen[ip] = now

    recent_fails[ip] = [t for t in recent_fails[ip] if (now - t).total_seconds() <= 3600]
    failed_count = len(recent_fails[ip])
    if row['status'] == 'Failed':
        recent_fails[ip].append(now)

    failed_attempts.append(failed_count)

df['time_since_last_seen_ip'] = time_deltas
df['failed_attempts_last_hour'] = failed_attempts

df.fillna({'time_since_last_seen_ip': -1, 'failed_attempts_last_hour': 0}, inplace=True)

# Text feature
df['log_line'] = df.apply(
    lambda row: f"{row['status']} password for {row['user']} from {row['ip']} port 22 ssh2", axis=1
)

# Vectorization
tfidf = TfidfVectorizer(max_features=100)
X_text = tfidf.fit_transform(df['log_line'])

# Structured features
structured_features = df[[
    'status_failed',
    'user_encoded',
    'hour',
    'is_internal_ip',
    'time_since_last_seen_ip',
    'failed_attempts_last_hour'
]]
scaler = StandardScaler()
X_structured = scaler.fit_transform(structured_features)

# Combine
X_combined = hstack([X_text, X_structured])
y = df['is_malicious_ip'].values

# === Stratified K-Fold + Hyperparameter Tuning ===
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

param_grid = {
    'n_estimators': [50, 100],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5]
}

best_pr_auc = 0
best_model = None
best_params = None

for n_estimators in param_grid['n_estimators']:
    for max_depth in param_grid['max_depth']:
        for min_samples_split in param_grid['min_samples_split']:
            print(f"Testing params: n_estimators={n_estimators}, max_depth={max_depth}, min_samples_split={min_samples_split}")
            pr_aucs = []

            for fold, (train_idx, test_idx) in enumerate(skf.split(X_combined, y)):
                X_train = hstack([X_text[train_idx], X_structured[train_idx]])
                X_test = hstack([X_text[test_idx], X_structured[test_idx]])
                y_train, y_test = y[train_idx], y[test_idx]

                clf = RandomForestClassifier(
                    n_estimators=n_estimators,
                    max_depth=max_depth,
                    min_samples_split=min_samples_split,
                    random_state=42
                )
                clf.fit(X_train, y_train)

                y_probs = clf.predict_proba(X_test)[:, 1]
                precision, recall, _ = precision_recall_curve(y_test, y_probs)
                pr_auc = auc(recall, precision)
                pr_aucs.append(pr_auc)

            mean_pr_auc = np.mean(pr_aucs)
            print(f"Mean PR-AUC across folds: {mean_pr_auc:.4f}")

            if mean_pr_auc > best_pr_auc:
                best_pr_auc = mean_pr_auc
                best_params = {
                    'n_estimators': n_estimators,
                    'max_depth': max_depth,
                    'min_samples_split': min_samples_split
                }
                best_model = copy.deepcopy(clf)

print(f"\nBest PR-AUC: {best_pr_auc:.4f} with params: {best_params}")

# Save best model to disk
joblib.dump(best_model, "best_rf_model.joblib")
print("Best model saved to best_rf_model.joblib")

# Optional: Final evaluation on full dataset (or you can hold out test set if you want)
y_pred = best_model.predict(X_combined)
print("\nFinal Classification Report on full dataset:")
print(classification_report(y, y_pred))