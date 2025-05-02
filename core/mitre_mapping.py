import re
import json
from datetime import datetime

# Minimal IOC to MITRE mapping table
IOC_MITRE_MAPPING = {
    "ip": {
        "suspicious_ip": "T1071.001",  # Application Layer Protocol: Web Protocols
    },
    "hash": {
        "malicious_hash": "T1105",     # Ingress Tool Transfer
    },
    "domain": {
        "suspicious_domain": "T1568.002",  # Dynamic Resolution
    }
}

# Regex patterns for IOC extraction
IOC_PATTERNS = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "hash": r"\b[a-fA-F0-9]{64}\b",  # SHA256
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
}

def extract_iocs_from_log(log_line):
    """Extract IPs, hashes, and domains from a log line."""
    iocs = {"ip": [], "hash": [], "domain": []}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, log_line)
        iocs[ioc_type].extend(matches)
    return iocs

def map_iocs_to_mitre(iocs):
    """Map extracted IOCs to MITRE ATT&CK techniques."""
    mappings = []
    for ioc_type, values in iocs.items():
        for value in values:
            technique_id = IOC_MITRE_MAPPING.get(ioc_type, {}).get("suspicious_" + ioc_type)
            if technique_id:
                mappings.append({
                    "ioc": value,
                    "type": ioc_type,
                    "mitre_technique": technique_id,
                    "timestamp": datetime.utcnow().isoformat()
                })
    return mappings

def analyze_log_file(log_path, output_path="mapped_iocs.json"):
    """Analyze a log file and write IOC mapping output."""
    results = []
    with open(log_path, "r") as f:
        for line in f:
            iocs = extract_iocs_from_log(line)
            mapped = map_iocs_to_mitre(iocs)
            if mapped:
                results.extend(mapped)
    
    with open(output_path, "w") as out:
        json.dump(results, out, indent=2)
    print(f"[+] Mapped IOCs written to {output_path}")

if __name__ == "__main__":
    analyze_log_file("logs/honeypot.log")
