# Threat Intelligence Aggregator

A Python-based tool designed to aggregate, normalize, and correlate Indicators of Compromise (IOCs) from various threat intelligence feeds. It supports both remote URL feeds and local files, processing them to generate unified blocklists and detailed threat reports.

## Features

*   **Multi-Source Aggregation**: Fetches threat data from configured URLs and local directories.
*   **Intelligent Parsing**: Automatically extracts IOCs using robust regular expressions.
    *   IPv4 Addresses (with validation for private/loopback ranges)
    *   Domains
    *   URLs
    *   Email Addresses
    *   File Hashes (MD5 and SHA256)
*   **Correlation & Risk Scoring**: Identifies indicators appearing across multiple sources and assigns risk scores (High/Medium/Low) based on frequency.
*   **Allowlisting**: Supports an allowlist to exclude trusted indicators.
*   **Automated Reporting**: Generates categorized blocklists (TXT) and a full JSON report with metadata.

## Installation

1.  **Clone the repository/Download source code**.
2.  **Install Dependencies**:
    The tool requires Python 3. Ensure you have the necessary packages (mainly `requests`).
    ```bash
    pip install -r requirements.txt
    ```
    *(If a requirements.txt is not provided, simply run `pip install requests`)*

## Usage

1.  **Prepare Input Data**:
    Place your raw data files (logs, CSVs, JSON, text) into the `Input_Feeds/` folder. The tool will process *all* files found in this directory.

2.  **Run the Tool**:
    Execute the main script:
    ```bash
    python3 main.py
    ```
    This script reads all files from `Input_Feeds/`, fetches data from configured URLs, and aggregates the results.

3.  **View Output**:
    The tool automatically creates the `Output/` folder (if it doesn't exist) and generates the following files:
    *   `blocklist_ips.txt`
    *   `blocklist_domains.txt`
    *   `blocklist_urls.txt`
    *   `blocklist_emails.txt`
    *   `blocklist_hashes.txt`
    *   `full_report.json`

## Input Feeds & Formats

This tool uses a content-agnostic parsing engine. You can interpret text from a wide variety of file formats found in the `Input_Feeds/` directory.

**What kind of inputs can you give it?**

The parser scans files for **regex patterns**, meaning it does not strictly require a specific file format like a rigid CSV or JSON schema. It extracts supported indicators from *any* text-based content.

Supported formats include:
*   **JSON files**: Complex nested structures (like STIX or custom API dumps).
*   **CSV files**: Comma-separated lists of indicators.
*   **Plain Text (.txt)**: Simple lists (one per line).
*   **Log files**: Raw server logs or unstructured text.

### Example Inputs

**1. JSON Input (`input.json`)**
The tool will automatically find the IP, domain, and hash values within the key-value pairs.
```json
[
  {
    "indicator": "192.168.1.1",
    "type": "ip",
    "note": "Malicious scanner"
  },
  {
    "domain": "bad-site.com"
  }
]
```

**2. Plain Text List**
```text
10.0.0.5
example-malware.com
admin@phishing.org
```

**3. Unstructured Text**
"Observed connection to 203.0.113.5 and downloaded file with hash a1b2c3d4e5f6..."
*(The tool will extract the IP and Hash from this sentence)*

### Supported Indicators
*   **IP Addresses**: Valid public IPv4 addresses.
*   **Domains**: Valid domain syntax.
*   **URLs**: HTTP/HTTPS links.
*   **Emails**: Standard email address formats.
*   **Hashes**: MD5 (32 chars) and SHA256 (64 chars).

## Allowlisting

If you want to exclude specific IPs, URLs, domains, or other indicators from the generated blocklists, you can add them to the `allowlist.txt` file.

1.  Open text file `allowlist.txt` (or create it if it doesn't exist).
2.  Add the indicators you want to allow (whitelist), one per line.
3.  The tool will check this file during processing. Any IP, Domain, URL, or Hash found in `allowlist.txt` will **not** be marked or included in the final blocklists or report.

**Example `allowlist.txt` content:**
```text
192.168.1.1
google.com
ExampleTrustedHash123
```
