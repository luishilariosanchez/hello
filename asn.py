import requests
import json
import random
import time
import concurrent.futures
from threading import Lock
import sys

print_lock = Lock()

def safe_print(*args, **kwargs):
    """Thread-safe print function"""
    with print_lock:
        print(*args, **kwargs)

# Read and extract AS numbers
with open('asn.txt', 'r') as f:
    asns = []
    for line in f:
        line = line.strip()
        if not line:
            continue

        # Extract AS number
        if 'AS' in line:
            for part in line.split():
                if part.startswith('AS'):
                    asn = part[2:]
                    if asn.isdigit():
                        asns.append(asn)
                        break
        elif line.isdigit():
            asns.append(line)
        elif 'AS' in line.upper():
            import re
            match = re.search(r'AS(\d+)', line.upper())
            if match:
                asns.append(match.group(1))

# Select random ASNs
if len(asns) > 100:
    random.seed(time.time())
    selected_asns = random.sample(asns, 100)
else:
    selected_asns = asns

safe_print(f"Processing {len(selected_asns)} AS numbers...")

# Worker function for thread pool
def fetch_asn_data(asn):
    """Fetch IPv4 prefixes for a single ASN with retry logic"""
    for attempt in range(3):
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            response = requests.get(url, timeout=10)
            data = response.json()

            ipv4_prefixes = []
            if 'data' in data and 'prefixes' in data['data']:
                for prefix_info in data['data']['prefixes']:
                    prefix = prefix_info.get('prefix', '')
                    if ':' not in prefix:  # IPv4 check
                        ipv4_prefixes.append(prefix)

            safe_print(f"AS{asn}: {len(ipv4_prefixes)} prefixes")
            return ipv4_prefixes

        except Exception:
            if attempt < 2:
                time.sleep(2)
                continue
            safe_print(f"AS{asn}: Failed after 3 attempts")
            return []

    return []

# Collect all prefixes
all_prefixes = []

# Process with thread pool
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(fetch_asn_data, asn) for asn in selected_asns]

    for future in concurrent.futures.as_completed(futures):
        prefixes = future.result()
        all_prefixes.extend(prefixes)

# Save to file
with open('ipv4.txt', 'w') as f:
    for prefix in all_prefixes:
        f.write(f"{prefix}\n")

safe_print(f"\nDone! Saved {len(all_prefixes)} IPv4 prefixes to ipv4.txt")
