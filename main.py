from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import joblib
import re
from datetime import datetime
import pandas as pd
from collections import defaultdict
from scipy.sparse import hstack
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from dateutil.parser import parse as parse_date

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI()

# === Load trained artifacts ===
model = joblib.load("model/best_rf_model.joblib")
tfidf = joblib.load("model/tfidf.joblib")
scaler = joblib.load("model/scaler.joblib")
threshold = 0.7

# === Input schema ===
class LogRequest(BaseModel):
    logs: List[str]

# === Regex for parsing log lines ===
log_pattern = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) '
    r'\S+ sshd\[(?P<pid>\d+)\]: '
    r'(?P<status>\w+) password for (?P<user>\w*) from (?P<ip>[\d.]+) port \d+ ssh2'
)

# === Trusted users for encoding ===
trusted_users = ['root', 'admin', 'user', 'test', 'guest', 'devops', 'john_doe', 'oracle']
trusted_users_map = {u: i for i, u in enumerate(trusted_users)}

# === Normalize status (e.g., "Failed" vs "failed")
def normalize_status(status: str) -> str:
    status = status.lower()
    if "fail" in status:
        return "Failed"
    elif "accept" in status:
        return "Accepted"
    return "Unknown"

# === API endpoint ===
@app.get("/test-db")
def test_db():
    data = supabase.table("ip_activity").select("*").execute()
    return data.data

@app.post("/classify")
def classify_logs(request: LogRequest):
    parsed_logs = []

    # Step 1: Parse all log lines
    for line in request.logs:
        match = log_pattern.match(line)
        if not match:
            continue

        parts = match.groupdict()
        parts['status'] = normalize_status(parts['status'])

        try:
            parts['timestamp'] = datetime.strptime(parts['timestamp'], "%b %d %H:%M:%S")
        except ValueError:
            continue

        parsed_logs.append(parts)

    if not parsed_logs:
        raise HTTPException(status_code=400, detail="No valid logs found.")

    # Step 2: Create DataFrame
    df = pd.DataFrame(parsed_logs)
    ips=df['ip'].unique().tolist()

    response = (
        supabase
        .table("ip_activity")
        .select("ip, last_seen, recent_failed_attempts")
        .in_("ip", ips)
        .execute()
    )
    rows = response.data

    last_seen_dict = {}
    failed_attempts_dict = {}

    for row in rows:
        ip = row['ip']
        last_seen_dict[ip] = (
            parse_date(row['last_seen']).replace(tzinfo=None) if row['last_seen'] else None
        )
        failed_attempts_dict[ip] = [
            parse_date(ts).replace(tzinfo=None) for ts in row['recent_failed_attempts']
        ] if row['recent_failed_attempts'] else []


    def calc_time_since_last_seen(ip, current_time):
        last = last_seen_dict.get(ip)
        if last is None:
            return -1  # default for unseen IPs
        return (current_time - last).total_seconds()

    def calc_failed_attempts_last_hour(ip, current_time):
        attempts = failed_attempts_dict.get(ip, [])
        # keep only timestamps within last hour relative to current_time
        return sum(1 for t in attempts if (current_time - t).total_seconds() <= 3600)

    # Step 3: Feature Engineering
    df['hour'] = df['timestamp'].dt.hour
    df['is_internal_ip'] = df['ip'].str.startswith("192.168.").astype(int)
    df['user_encoded'] = df['user'].apply(lambda x: trusted_users_map.get(x, -1))
    df['status_failed'] = df['status'].apply(lambda s: 1 if s == 'Failed' else 0)
    df['time_since_last_seen_ip'] = df.apply(lambda row: calc_time_since_last_seen(row['ip'], row['timestamp']), axis=1)
    df['failed_attempts_last_hour'] = df.apply(lambda row: calc_failed_attempts_last_hour(row['ip'], row['timestamp']), axis=1)

    # Step 4: Text feature (TF-IDF)
    df['log_line'] = df.apply(
        lambda row: f"{row['status']} password for {row['user']} from {row['ip']} port 22 ssh2", axis=1
    )
    X_text = tfidf.transform(df['log_line'])

    # Step 5: Structured features
    structured_features = df[[
        'status_failed',
        'user_encoded',
        'hour',
        'is_internal_ip',
        'time_since_last_seen_ip',
        'failed_attempts_last_hour'
    ]]
    X_structured = scaler.transform(structured_features)

    # Step 6: Combine
    X_combined = hstack([X_text, X_structured])

    # Step 7: Predict
    probs = model.predict_proba(X_combined)[:, 1]
    preds = (probs >= threshold).astype(int)

    # Step 8: Return results
    results = []
    for i, log in enumerate(parsed_logs):
        results.append({
            "timestamp": log["timestamp"].isoformat(),
            "user": log["user"],
            "ip": log["ip"],
            "status": log["status"],
            "probability": round(float(probs[i]), 4),
            "classification": "Malicious" if preds[i] else "Benign"
        })

    return {
        "threshold": threshold,
        "results": results,
        "num_logs": len(results),
        "num_malicious": int(preds.sum()),
        "num_benign": int(len(results) - preds.sum())
    }