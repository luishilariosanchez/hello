# asn_dynamic.py
import sys
import math

def distribute_asns(instance_num, total_instances):
    """
    Distribute ASNs evenly across all instances
    """
    with open('asn.txt', 'r') as f:
        all_asns = [line.strip() for line in f if line.strip()]
    
    total_lines = len(all_asns)
    base_size = total_lines // total_instances
    remainder = total_lines % total_instances
    
    # Calculate chunks
    chunks = []
    start = 0
    for i in range(total_instances):
        size = base_size + (1 if i < remainder else 0)
        chunks.append(all_asns[start:start + size])
        start += size
    
    # Get chunk for this instance
    instance_idx = instance_num - 1
    instance_asns = chunks[instance_idx]
    
    # Save to file
    output_file = f'asn_instance_{instance_num}.txt'
    with open(output_file, 'w') as f:
        f.write('\n'.join(instance_asns))
    
    print(f"Instance {instance_num}: {len(instance_asns)} ASNs")
    return instance_asns

if __name__ == "__main__":
    instance_num = int(sys.argv[1])
   
