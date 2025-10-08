import json
import os

def extract_highest_dns_lookup(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    tool_name = data[0]['toolName'] if data else None
    if not tool_name:
        return None, []
    
    extractions = []
    for measurement in data:
        measurement_number = measurement['measurementNumber']
        max_dns = 0
        # Check all file sizes (25MB, 10MB, 5MB) for the highest dnsLookup
        for transfer in measurement['fileTransfers']:
            filename = transfer['filename'].lower()
            if ('25mb' in filename or '10mb' in filename or '5mb' in filename) and transfer['dnsLookup'] != 0:
                if transfer['dnsLookup'] > max_dns:
                    max_dns = transfer['dnsLookup']
        if max_dns > 0:  # Only append if a valid (non-zero) dnsLookup was found
            extractions.append({
                'measurementNumber': measurement_number,
                'dnsLookup': max_dns
            })
    
    return tool_name, extractions

def main(directory='.'):
    for filename in os.listdir(directory):
        if filename.endswith('_combined.json'):
            file_path = os.path.join(directory, filename)
            tool_name, dns_data = extract_highest_dns_lookup(file_path)
            if tool_name:
                output_filename = f"{tool_name}_dns.json"
                with open(output_filename, 'w') as out_f:
                    json.dump({
                        'tool': tool_name,
                        'data': dns_data
                    }, out_f, indent=4)
                print(f"Processed {filename} and saved to {output_filename}")

if __name__ == "__main__":
    main()
