import random
from datetime import datetime, timedelta
from collections import defaultdict
import json

# Settings
num_entries = 1000
ips = [f"192.168.1.{i}" for i in range(1, 50)]

ip_user_mapping = {}

for i in range(1, 10):
    ip_user_mapping[f"192.168.1.{i}"] = ['root', 'admin', 'usr']

for i in range(10, 20):
    ip_user_mapping[f"192.168.1.{i}"] = ['user', 'test', 'gst']

for i in range(20, 30):
    ip_user_mapping[f"192.168.1.{i}"] = ['guest', 'devops', 'rot']

for i in range(30, 40):
    ip_user_mapping[f"192.168.1.{i}"] = ['john_doe', 'oracle', '']

for i in range(40, 50):
    ip_user_mapping[f"192.168.1.{i}"] = ['admin', 'user', 'tst']


statuses = ['Accepted', 'Failed']

log_template = "{timestamp} myhost sshd[{pid}]: {status} password for {user} from {ip} port 22 ssh2\n"

ip_fail_count = defaultdict(int)
ip_seen_count = defaultdict(int)

with open("simulated_auth.log", "w") as f:
    for i in range(num_entries):
        dt = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        timestamp = dt.strftime("%b %d %H:%M:%S")
        pid = random.randint(1000, 9999)

        ip = random.choice(ips)
        user = random.choices(ip_user_mapping[ip], weights=[0.4, 0.5, 0.1])[0]
        ip_seen_count[ip] += 1

        # Inject noise: 5% of the time, flip the logic
        noise = random.random()
        if noise < 0.025:
            # False positive: make benign IP look malicious
            status = "Failed"
        elif noise < 0.05:
            # False negative: make malicious IP look benign
            status = "Accepted"
        else:
            # Original logic
            if ip_fail_count[ip] >= 5 or ip_seen_count[ip] >= 5 or user == ip_user_mapping[ip][2]:
                status = random.choices(statuses, weights=[0.3, 0.7])[0]
            else:
                status = random.choices(statuses, weights=[0.7, 0.3])[0]

        if status == 'Failed':
            ip_fail_count[ip] += 1


        log_entry = log_template.format(timestamp=timestamp, pid=pid, status=status, user=user, ip=ip)
        f.write(log_entry)

malicious_ips = []
label_counts = {"malicious": 0, "benign": 0}
top_offenders = {}
dynamic_threshold = random.uniform(0.6, 0.8)
for ip in ips:
    seen = ip_seen_count[ip]
    fails = ip_fail_count[ip]
    if seen > 0:
        fail_rate = fails / seen
        if fail_rate >= dynamic_threshold:
            malicious_ips.append(ip)
            label_counts["malicious"] += 1
            top_offenders[ip] = {
                "fail_rate": round(fail_rate, 2),
                "threshold_used": round(dynamic_threshold, 2),
                "failed": fails,
                "seen": seen
            }
        else:
            label_counts["benign"] += 1

metadata = {
    "version": "1.0",
    "generated_at": datetime.now().isoformat(),
    "threshold": dynamic_threshold,
    "num_entries": num_entries,
    "num_malicious_ips": len(malicious_ips),
    "malicious_ips": malicious_ips,
    "label_counts": label_counts,
    "top_offenders": top_offenders
}

with open("malicious_ips.json", "w") as f:
    json.dump(metadata, f, indent=2)