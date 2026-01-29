import ipaddress
import os

def validate_ip(ip_str):
    """
    Validates if a string is a proper IPv4 address.
    Ref: [Source: 56] - ipaddress library for IP validation.
    """
    try:
        # strict=False allows for some loose formatting, but we generally want strict
        ip_obj = ipaddress.IPv4Address(ip_str)
        return not ip_obj.is_private and not ip_obj.is_loopback
    except ipaddress.AddressValueError:
        return False

def identify_hash_type(hash_str):
    """
    Identifies if a hash is MD5 or SHA256 based on length.
    Ref: [Source: 57] - Verifying hash formats.
    """
    length = len(hash_str)
    if length == 32:
        return "md5"
    elif length == 64:
        return "sha256"
    return "unknown"

def load_local_file(filepath):
    """
    Reads content from a local file (e.g., a local blacklist).
    Ref: [Source: 60] - Local IOC files.
    """
    if not os.path.exists(filepath):
        print(f"[!] Error: File {filepath} not found.")
        return ""
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"[!] Error reading file {filepath}: {e}")
        return ""