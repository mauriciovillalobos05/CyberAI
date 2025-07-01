import re
from datetime import datetime
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

malicious_ips = [f"203.0.113.{i}" for i in range(10, 15)]
users = ['root', 'admin', 'user', 'test', 'guest']

log_pattern = re.compile(
    r'^(?P<timestamp>\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}) '
    r'\S+ sshd\[(?P<pid>\d+)\]: '
    r'(?P<status>\w+) password for (?P<user>\w+) from (?P<ip>[\d.]+) port \d+ ssh2'
)

parsed_logs = []

with open("simulated_auth.log", "r") as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            log_data = match.groupdict()
            parsed_logs.append(log_data)

feature_vectors = []
labels = []

for log in parsed_logs:
    # Feature 1: status
    status_val = 1 if log["status"] == "Failed" else 0

    # Feature 2: user (label encode: map to integer index)
    user_val = users.index(log["user"]) if log["user"] in users else -1

    # Feature 3: hour
    try:
        timestamp_obj = datetime.strptime(log["timestamp"], "%b %d %H:%M:%S")
        hour_val = timestamp_obj.hour
    except ValueError:
        hour_val = -1  # or skip the entry

    # Feature 4: is_internal_ip
    is_internal_ip = 1 if log["ip"].startswith("192.168.") else 0

    # Feature 5: is known malicious
    ip_is_malicious = 1 if log["ip"] in malicious_ips else 0

    # Collect features
    features = [status_val, user_val, hour_val, is_internal_ip]
    feature_vectors.append(features)

    # Label (what we want the model to predict)
    labels.append(ip_is_malicious)

print("Feature vector:", feature_vectors[0])
print("Label:", labels[0])

X = np.array(feature_vectors)
y = np.array(labels)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)


clf = RandomForestClassifier()
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)

print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))