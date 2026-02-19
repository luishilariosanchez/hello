import sys
import requests
import socket

def get_ipv4_prefixes_from_asn(asn):
    """
    Return list of unique IPv4 prefixes announced by ASN using RIPEstat API (primary).
    Fallback to RADb WHOIS if HTTP fails.
    """
    # Primary: RIPEstat API
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        prefixes = []
        for p in data.get('data', {}).get('prefixes', []):
            prefix = p.get('prefix')
            if prefix and '/' in prefix and ':' not in prefix:  # IPv4 only
                prefixes.append(prefix)
        if prefixes:
            return list(set(prefixes))  # dedup
    except Exception as e:
        print(f"RIPEstat error for ASN {asn}: {e}")

    # Fallback: RADb WHOIS
    print(f"Falling back to RADb WHOIS for ASN {asn}")
    query = f"!gAS{asn}\n"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('whois.radb.net', 43))
        sock.send(query.encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        lines = response.decode().splitlines()
        prefixes = []
        for line in lines:
            line = line.strip()
            if line and '/' in line and line[0].isdigit() and ':' not in line:
                prefixes.append(line.split()[0])  # prefix is first field
        return list(set(prefixes))
    except Exception as e:
        print(f"WHOIS error for ASN {asn}: {e}")
        return []

def distribute_asns(instance_num, total_instances):
    """Distribute ASNs evenly across all instances and return this instance's ASNs."""
    with open('asn.txt', 'r') as f:
        all_asns = [line.strip() for line in f if line.strip()]

    total_lines = len(all_asns)
    if total_lines == 0:
        print("ERROR: asn.txt is empty")
        return []

    if instance_num < 1 or instance_num > total_instances:
        print("ERROR: Invalid instance number")
        return []

    base_size = total_lines // total_instances
    remainder = total_lines % total_instances

    start = 0
    instance_asns = []
    for i in range(total_instances):
        size = base_size + (1 if i < remainder else 0)
        if i == instance_num - 1:
            instance_asns = all_asns[start:start + size]
            break
        start += size

    # Save ASNs for this instance (original behavior)
    asn_output = f'asn_instance_{instance_num}.txt'
    with open(asn_output, 'w') as f:
        f.write('\n'.join(instance_asns))
    print(f"Instance {instance_num}: {len(instance_asns)} ASNs saved to {asn_output}")

    return instance_asns

def asns_to_ipv4_file(instance_num, total_instances):
    """Main function: Get instance ASNs, convert to IPv4 prefixes only, write to file."""
    instance_asns = distribute_asns(instance_num, total_instances)
    if not instance_asns:
        return

    all_ipv4_prefixes = []
    for asn in instance_asns:
        # Normalize ASN (strip 'AS' if present)
        asn_num = asn.upper().replace('AS', '')
        print(f"Fetching IPv4 for ASN {asn_num}...")
        prefixes = get_ipv4_prefixes_from_asn(asn_num)
        all_ipv4_prefixes.extend(prefixes)
        print(f"  Found {len(prefixes)} prefixes")

    # Global deduplication
    seen = set()
    unique_ipv4 = [p for p in all_ipv4_prefixes if not (p in seen or seen.add(p))]

    ipv4_output = f'ipv4_instance_{instance_num}.txt'
    with open(ipv4_output, 'w') as f:
        f.write('\n'.join(unique_ipv4))

    print(f"\nInstance {instance_num}: {len(unique_ipv4)} unique IPv4 prefixes written to {ipv4_output}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python asn_dynamic.py <instance_num> <total_instances>")
        sys.exit(1)

    instance_num = int(sys.argv[1])
    total_instances = int(sys.argv[2])
    asns_to_ipv4_file(instance_num, total_instances)
