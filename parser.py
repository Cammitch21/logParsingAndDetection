import re
import datetime
import pandas as pd
from collections import Counter
import geoip2.database


# File Reading
file_path = "sample_logs/access_sample.log"

def read_log(file_path):
    with open(file_path, "r") as file:
        for line in file:
            yield line.strip()
 
# File Regex
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(?P<datetime>[^\]]+)\]\s"(?P<request>[^"]+)"\s(?P<status>\d{3})\s(?P<size>\d+)\s"(?P<url>[^"]+)"\s"(?P<system>[^"]+)"'
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
df_404 = df[df['status'] == 404]
ip_404_counts = df_404['ip'].value_counts()
ip_404_df = ip_404_counts.reset_index()
ip_404_df.columns = ['ip','404_count']

ip_404_df.head(10).to_csv('reports/sample_report.csv')

# GeoLite IP Location Lookup (Optional)

geoip_path = 'data\GeoLite2-City.mmdb'

reader = geoip2.database.Reader(geoip_path)

def lookup_geo(ip):
    try:
        response = reader.city(ip)
        return {
            'country': response.country.name,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except:
        return{
            'country': None,
            'city': None,
            'latitude': None,
            'longitude': None
        }
        raise

# Adding GeoLookup to Dataframe 
unique_ips = df['ip'].dropna().unique()

geo_data = {ip: lookup_geo(ip) for ip in unique_ips}

df['country'] = df['ip'].map(lambda x: geo_data.get(x,{}).get('country'))
df['city'] = df['ip'].map(lambda x: geo_data.get(x, {}).get('city'))

# Outputting Dataframe to a csv
df.head(10).to_csv('reports/sample_geo_report.csv', index=False)

# Combining Suspicious activity with geolocation data
geo_info = ip_404_df['ip'].apply(lookup_geo)

final_df = pd.concat([ip_404_df, geo_info], axis=1)
print(final_df)
final_df.head(10).to_csv('reports/sample_suspicious_geo_report.csv')