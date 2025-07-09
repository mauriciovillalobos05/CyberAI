import random
from datetime import datetime, timedelta

# Settings
num_entries = 1000
malicious_ips = [f"203.0.113.{i}" for i in range(10, 15)]
normal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
weird_ips = ["10.0.0.5", "172.16.2.3", "invalid_ip"]

all_users = ['root', 'admin', 'user', 'test', 'guest', 'devops', 'john_doe', 'oracle']
statuses = ['Accepted', 'Failed']
status_typos = ['Faild', 'Accpted']

# Probabilities
malicious_ratio = 0.08  # 8% entries are attacks
typo_chance = 0.01      # 1% of entries contain typos
missing_user_chance = 0.005
weird_ip_chance = 0.02

log_template = "{timestamp} myhost sshd[{pid}]: {status} password for {user} from {ip} port 22 ssh2\n"

with open("simulated_auth.log", "w") as f:
    for i in range(num_entries):
        dt = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        timestamp = dt.strftime("%b %d %H:%M:%S")
        pid = random.randint(1000, 9999)

        is_attack = random.random() < malicious_ratio
        has_typo = random.random() < typo_chance
        use_weird_ip = random.random() < weird_ip_chance

        if is_attack:
            ip = random.choice(malicious_ips)
            user = random.choice(all_users)
            status = 'Failed' if random.random() < 0.9 else 'Accepted'  # attacker rarely succeeds
        else:
            ip = random.choice(normal_ips)
            user = random.choice(all_users)
            status = random.choices(statuses, weights=[1, 5])[0]  # mostly success

        # Inject some noise
        if has_typo:
            status = random.choice(status_typos)
        if use_weird_ip:
            ip = random.choice(weird_ips)
        if random.random() < missing_user_chance:
            user = ""

        log_entry = log_template.format(timestamp=timestamp, pid=pid, status=status, user=user, ip=ip)
        f.write(log_entry)