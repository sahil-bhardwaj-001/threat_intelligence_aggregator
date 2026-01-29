import requests
import time
import os
from .parser import IOCParser

class ThreatAggregator:
    def __init__(self):
        self.parser = IOCParser()
        self.all_iocs = [] # List to store normalized data
        self.stats = {
            'feeds_processed': 0,
            'total_unique_indicators': 0
        }
        self.allowlist = set()

    def set_allowlist(self, allowlist):
        """Sets the allowlist of indicators to ignore."""
        self.allowlist = set(allowlist)

    def fetch_feed(self, url, feed_name):
        """Downloads data from a URL and parses it."""
        print(f"[*] Fetching feed: {feed_name}...")
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                self.process_content(response.text, feed_name)
                self.stats['feeds_processed'] += 1
            else:
                print(f"[!] Failed to fetch {feed_name}: Status {response.status_code}")
        except Exception as e:
            print(f"[!] Error fetching {feed_name}: {e}")

    def process_local_feeds(self, directory):
        """Reads all files in a directory and processes them as feeds."""
        if not os.path.exists(directory):
            print(f"[!] Directory {directory} does not exist.")
            return

        print(f"[*] Processing local feeds from {directory}...")
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self.process_content(content, f"Local File: {filename}")
                        self.stats['feeds_processed'] += 1
                except Exception as e:
                    print(f"[!] Error reading local file {filename}: {e}")

    def process_content(self, content, source_name):
        """Extracts IOCs and normalizes them[cite: 32]."""
        iocs = self.parser.extract_iocs(content)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Normalization: Create a unified structure
        for ip in iocs['ips']:
            if ip not in self.allowlist:
                self.all_iocs.append({'value': ip, 'type': 'ip', 'source': source_name, 'timestamp': timestamp})
        for domain in iocs['domains']:
             if domain not in self.allowlist:
                self.all_iocs.append({'value': domain, 'type': 'domain', 'source': source_name, 'timestamp': timestamp})
        for url in iocs['urls']:
             if url not in self.allowlist:
                self.all_iocs.append({'value': url, 'type': 'url', 'source': source_name, 'timestamp': timestamp})
        for email in iocs['emails']:
             if email not in self.allowlist:
                self.all_iocs.append({'value': email, 'type': 'email', 'source': source_name, 'timestamp': timestamp})
        for file_hash in iocs['hashes']:
             if file_hash not in self.allowlist:
                self.all_iocs.append({'value': file_hash, 'type': 'hash', 'source': source_name, 'timestamp': timestamp})
        
        print(f"    -> Extracted {len(iocs['ips']) + len(iocs['domains']) + len(iocs['hashes']) + len(iocs['urls']) + len(iocs['emails'])} indicators.")

    def correlate_data(self):
        """
        Identify indicators appearing across multiple feeds.
        Prioritize repeated indicators as high-risk[cite: 36].
        """
        correlation_map = {}

        for item in self.all_iocs:
            value = item['value']
            if value not in correlation_map:
                correlation_map[value] = {
                    'type': item['type'],
                    'count': 0,
                    'sources': set(),
                    'risk_score': 'Low'
                }
            
            correlation_map[value]['count'] += 1
            correlation_map[value]['sources'].add(item['source'])

        # Assign Risk Scores based on frequency
        for value, data in correlation_map.items():
            if data['count'] >= 3:
                data['risk_score'] = 'High'
            elif data['count'] == 2:
                data['risk_score'] = 'Medium'
        
        self.stats['total_unique_indicators'] = len(correlation_map)
        return correlation_map