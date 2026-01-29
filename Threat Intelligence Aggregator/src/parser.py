import re
from .utils import validate_ip, identify_hash_type  # Import from utils

class IOCParser:
    def __init__(self):
        # Regex patterns 
        self.patterns = {
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
            'url': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
        }

    def extract_iocs(self, content):
        extracted_data = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'hashes': set(),
        }

        # 1. Extract and Validate IPs using utils.py
        raw_ips = re.findall(self.patterns['ip'], content)
        for ip in raw_ips:
            if validate_ip(ip):  # Using the helper function
                extracted_data['ips'].add(ip)

        # 2. Extract URLs
        raw_urls = re.findall(self.patterns['url'], content)
        for url in raw_urls:
            extracted_data['urls'].add(url)

        # 3. Extract Emails
        raw_emails = re.findall(self.patterns['email'], content)
        for email in raw_emails:
            extracted_data['emails'].add(email)

        # 4. Extract Domains
        raw_domains = re.findall(self.patterns['domain'], content)
        for domain in raw_domains:
            if not re.match(self.patterns['ip'], domain) and not any(domain in url for url in extracted_data['urls']):
                 extracted_data['domains'].add(domain)

        # 5. Extract and Identify Hashes using utils.py
        raw_md5 = re.findall(self.patterns['md5'], content)
        raw_sha256 = re.findall(self.patterns['sha256'], content)
        
        # Combine and verify
        for h in raw_md5 + raw_sha256:
            if identify_hash_type(h) != "unknown":
                extracted_data['hashes'].add(h)

        return extracted_data