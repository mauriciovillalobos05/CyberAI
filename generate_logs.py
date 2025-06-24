import random
from datetime import datetime, timedelta

# Settings
num_entries = 1000
malicious_ips = [f"203.0.113.{i}" for i in range(10, 15)]  # Simulated attackers
normal_ips = [f"192.168.1.{i}" for i in range(1, 30)]  # Internal/legit users
users = ['root', 'admin', 'user', 'test', 'guest']
statuses = ['Accepted', 'Failed']

# Log entry template
log_template = "{timestamp} myhost sshd[{pid}]: {status} password for {user} from {ip} port 22 ssh2\n"

# Output file
with open("simulated_auth.log", "w") as f:
    for _ in range(num_entries):
        # Timestamp
        dt = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        timestamp = dt.strftime("%b %d %H:%M:%S")

        # Decide if the entry is malicious
        is_attack = random.random() < 0.3  # 30% chance of being a brute-force entry

        if is_attack:
            ip = random.choice(malicious_ips)
            user = random.choice(users)
            status = 'Failed'
        else:
            ip = random.choice(normal_ips)
            user = random.choice(users)
            status = random.choices(statuses, weights=[1, 4])[0]  # Mostly Failed

        pid = random.randint(1000, 9999)

        log_entry = log_template.format(timestamp=timestamp, pid=pid, status=status, user=user, ip=ip)
        f.write(log_entry)
