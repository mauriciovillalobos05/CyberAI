import re
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from scipy.sparse import hstack

# === KNOWN VALUES ===
malicious_ips = [f"203.0.113.{i}" for i in range(10, 15)]
trusted_users = ['root', 'admin', 'user', 'test', 'guest']

# === REGEX FOR LOG LINE PARSING ===
log_pattern = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) '
    r'\S+ sshd\[(?P<pid>\d+)\]: '
    r'(?P<status>\w+) password for (?P<user>\w*) from (?P<ip>[\d.]+) port \d+ ssh2'
)

# === NORMALIZATION FUNCTION ===
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
                continue  # Skip malformed timestamps
            logs.append(log)

# === LOAD TO PANDAS ===
df = pd.DataFrame(logs)

# === FEATURE ENGINEERING ===
df['hour'] = df['timestamp'].dt.hour
df['is_internal_ip'] = df['ip'].str.startswith("192.168.").astype(int)
df['is_malicious_ip'] = df['ip'].isin(malicious_ips).astype(int)
df['user_encoded'] = df['user'].apply(lambda x: trusted_users.index(x) if x in trusted_users else -1)
df['status_failed'] = df['status'].apply(lambda s: 1 if s == 'Failed' else 0)

# === TIME-BASED FEATURES ===
df = df.sort_values(by='timestamp')
last_seen = {}
recent_fails = defaultdict(list)
time_deltas = []

for idx, row in df.iterrows():
    ip = row['ip']
    now = row['timestamp']

    last_time = last_seen.get(ip)
    delta = (now - last_time).total_seconds() if last_time else -1
    time_deltas.append(delta)
    last_seen[ip] = now

    # Count failed attempts from same IP in last hour
    recent_fails[ip] = [t for t in recent_fails[ip] if (now - t).total_seconds() <= 3600]
    failed_count = len(recent_fails[ip])
    if row['status'] == 'Failed':
        recent_fails[ip].append(now)

    df.loc[idx, 'failed_attempts_last_hour'] = failed_count

df['time_since_last_seen_ip'] = time_deltas
df.fillna({'time_since_last_seen_ip': -1, 'failed_attempts_last_hour': 0}, inplace=True)

# === TEXT FEATURE FOR NLP (TF-IDF) ===
df['log_line'] = df.apply(
    lambda row: f"{row['status']} password for {row['user']} from {row['ip']} port 22 ssh2", axis=1
)

# === TF-IDF VECTORIZATION ===
tfidf = TfidfVectorizer(max_features=100)
X_text = tfidf.fit_transform(df['log_line'])

# === STRUCTURED FEATURES ===
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

# === COMBINE TEXT + STRUCTURED FEATURES ===
X_combined = hstack([X_text, X_structured])
y = df['is_malicious_ip'].values

# === TRAIN/TEST SPLIT & MODEL ===
X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)

# === EVALUATION ===
print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))

# OPTIONAL: Save for analysis
df.to_csv("labeled_logs.csv", index=False)