import re
import datetime

# File Reading
file_path = "sample_logs/small_sample.log"

def read_log(file_path):
    with open(file_path, "r") as file:
        for line in file:
            yield line.strip()


for log_entry in read_log(file_path):
    print("log_entry")    

# File Regex

log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(?P<datetime>[^\]]+)\]\s"(?P<request>[^"]+)"\s(?P<status>\d{3})\s(?P<size>\d+)\s["](?P<url>[^"]+)["]\s["](?P<system>[^"]+)["]'
)

match = log_pattern.match(log_entry)
print(match)
