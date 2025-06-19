# Apache Log Parser with Suspicious IP Detection and GeoIP Enrichment

This Python project parses Apache access logs, identifies potentially suspicious IP addresses based on 404 error activity, and enriches them with GeoIP data (country, city, coordinates). It generates a structured CSV report of flagged IPs, useful for security monitoring or SOC workflows.

To use the program:

1. Clone the repository
2. Install the dependencies in the requirements.txt file
3. Download and add GeoLite2-City.mmdb database to the data folder.
     - You can create an account and download the file from this website https://www.maxmind.com
4. Run the program

This program was developed as a part of my Cyber Security portfolio that focuses on SOC tools.
