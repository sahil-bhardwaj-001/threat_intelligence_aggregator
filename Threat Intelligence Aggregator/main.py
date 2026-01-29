import os
import json
from src.aggregator import ThreatAggregator

# Example OSINT Feeds
# Load Configuration
def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

CONFIG = load_config()
THREAT_FEEDS = CONFIG["threat_feeds"]
OUTPUT_DIR = CONFIG["output_dir"]

def save_blocklists(correlated_data):
    """Generates text files for Firewalls/EDRs[cite: 39]."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    ips = []
    domains = []
    hashes = []
    urls = []
    emails = []

    for ioc, data in correlated_data.items():
        # Add to blocklist
        if data['type'] == 'ip':
            ips.append(ioc)
        elif data['type'] == 'domain':
            domains.append(ioc)
        elif data['type'] == 'hash':
            hashes.append(ioc)
        elif data['type'] == 'url':
            urls.append(ioc)
        elif data['type'] == 'email':
            emails.append(ioc)

    # Write files
    with open(f"{OUTPUT_DIR}/blocklist_ips.txt", "w") as f:
        f.write("\n".join(ips))
    with open(f"{OUTPUT_DIR}/blocklist_domains.txt", "w") as f:
        f.write("\n".join(domains))
    with open(f"{OUTPUT_DIR}/blocklist_hashes.txt", "w") as f:
        f.write("\n".join(hashes))
    with open(f"{OUTPUT_DIR}/blocklist_urls.txt", "w") as f:
        f.write("\n".join(urls))
    with open(f"{OUTPUT_DIR}/blocklist_emails.txt", "w") as f:
        f.write("\n".join(emails))

    print(f"[+] Blocklists saved to {OUTPUT_DIR}/")

def save_report(correlated_data, stats):
    """Saves a detailed JSON report[cite: 44]."""
    # Convert sets to lists for JSON serialization
    for data in correlated_data.values():
        data['sources'] = list(data['sources'])

    report = {
        "summary": stats,
        "intelligence": correlated_data
    }

    with open(f"{OUTPUT_DIR}/full_report.json", "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Full report saved to {OUTPUT_DIR}/full_report.json")

def main():
    print("=== Threat Intelligence Aggregator Started ===")
    
    aggregator = ThreatAggregator()

    # Load Allowlist
    allowlist_path = CONFIG.get("allowlist_file", "allowlist.txt")
    if os.path.exists(allowlist_path):
        with open(allowlist_path, "r") as f:
            lines = f.read().splitlines()
            allowlist = {line.strip() for line in lines if line.strip() and not line.startswith("#")}
            aggregator.set_allowlist(allowlist)
            print(f"[*] Loaded allowlist with {len(allowlist)} entries.")

    # 1. Load Feeds
    # Process Local Feeds
    input_feeds_dir = CONFIG.get("input_feeds_dir", "Input_Feeds")
    aggregator.process_local_feeds(input_feeds_dir)

    for name, url in THREAT_FEEDS.items():
        aggregator.fetch_feed(url, name)

    # 2. Correlate Data
    print("[*] Correlating data across feeds...")
    correlated_data = aggregator.correlate_data()

    # 3. Generate Outputs
    save_blocklists(correlated_data)
    save_report(correlated_data, aggregator.stats)

    print("=== Processing Complete ===")

if __name__ == "__main__":
    main()