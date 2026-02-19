# asn_dynamic.py
import sys

def distribute_asns(instance_num, total_instances):
    """
    Distribute ASNs evenly across all instances
    """

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

    for i in range(total_instances):
        size = base_size + (1 if i < remainder else 0)

        if i == instance_num - 1:
            instance_asns = all_asns[start:start + size]
            break

        start += size

    output_file = f'asn_instance_{instance_num}.txt'

    with open(output_file, 'w') as f:
        f.write('\n'.join(instance_asns))

    print(f"Instance {instance_num}: {len(instance_asns)} ASNs")

    return instance_asns


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python asn_dynamic.py <instance_num> <total_instances>")
        sys.exit(1)

    instance_num = int(sys.argv[1])
    total_instances = int(sys.argv[2])

    distribute_asns(instance_num, total_instances)
