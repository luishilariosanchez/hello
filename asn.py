import sys
import requests  # pip install requests

def get_ipv4_prefixes_from_asn(asn):
    """Return list of IPv4 prefixes for a given ASN."""
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # API returns IPv4 prefixes under data['data']['ipv4_prefixes'][]
        return [p['prefix'] for p in data.get('data', {}).get('ipv4_prefixes', [])]
    except Exception as e:
        print(f"Error getting prefixes for ASN {asn}: {e}")
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

    # Save ASNs for this instance (optional)
    asn_output = f"asn_instance_{instance_num}.txt"
    with open(asn_output, 'w') as f:
        f.write('\n'.join(instance_asns))
    print(f"Instance {instance_num}: {len(instance_asns)} ASNs")

    return instance_asns

def asns_to_ipv4_file(instance_num, total_instances):
    """For this instance: get its ASNs, convert to IPv4 prefixes only, write to file."""
    instance_asns = distribute_asns(instance_num, total_instances)
    if not instance_asns:
        return

    ipv4_prefixes = []
    for asn in instance_asns:
        # strip possible leading 'AS'
        asn_num = asn.upper().replace('AS', '')
        prefixes = get_ipv4_prefixes_from_asn(asn_num)
        ipv4_prefixes.extend(prefixes)

    # deduplicate while preserving order
    seen = set()
    unique_ipv4 = []
    for p in ipv4_prefixes:
        if p not in seen:
            seen.add(p)
            unique_ipv4.append(p)

    ipv4_output = f"ipv4_instance_{instance_num}.txt"
    with open(ipv4_output, 'w') as f:
        f.write('\n'.join(unique_ipv4))

    print(f"Instance {instance_num}: {len(unique_ipv4)} IPv4 prefixes written to {ipv4_output}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python asn_dynamic.py <instance_num> <total_instances>")
        sys.exit(1)

    instance_num = int(sys.argv[1])
    total_instances = int(sys.argv[2])
    asns_to_ipv4_file(instance_num, total_instances)
