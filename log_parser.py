import re

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

# Example output
for log in parsed_logs[:5]:  # Show only the first 5 parsed entries
    print(log)
