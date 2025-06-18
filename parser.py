import re
import datetime
import pandas as pd
from collections import Counter


# File Reading
file_path = "sample_logs/access.log"

def read_log(file_path):
    with open(file_path, "r") as file:
        for line in file:
            yield line.strip()
 
# File Regex
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(?P<datetime>[^\]]+)\]\s"(?P<request>[^"]+)"\s(?P<status>\d{3})\s(?P<size>\d+)\s["](?P<url>[^"]+)["]\s["](?P<system>[^"]+)["]'
)

# Parsing each Log Line
def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        entry = match.groupdict()
        # Converting Status and Size to Integers
        entry['status'] = int(entry['status'])
        entry['size'] = int(entry['size'])
        return entry
    else:
        return None
    
# Processing the whole log
def parse_log_file(file_path):
    parsed_entries = []
    for line in read_log(file_path):
        entry = parse_log_line(line)
        if entry:
            parsed_entries.append(entry)
    return parsed_entries

entries = parse_log_file(file_path)
print(f"Number of Entries Parsed: {len(entries)}")


def count_status(entries):
    status_codes = [entry['status'] for entry in entries]
    return Counter(status_codes)

status_counts = count_status(entries)
print("Status Code Counts:", status_counts)

# Using Panads to extract suspicious activity in the log file
df = pd.DataFrame(entries)
suspicious = df[df['status'] == 404].groupby('ip').size()
print(suspicious.head())

suspicious.to_csv('report.csv')