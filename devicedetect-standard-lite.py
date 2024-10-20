import nmap
import re
from collections import defaultdict
from device_type_category import DEVICE_TYPE_CATEGORY  # Assuming DEVICE_TYPE_CATEGORY is in the mapping file

# Function to perform intense scan using nmap
def perform_nmap_scan(ip):
    scanner = nmap.PortScanner()
    print(f"Running intense scan on {ip}...")
    nmap_arg = f"-O -sU -sS T:1-65535,U:67,68,111,123,137,138,161,162,500,554,631,1701,1812,1813,1900,1935,2049,3702,4500,5060,5061,5353,10000,16384,32767 -T4 --min-rate 500 --min-parallelism 50 --max-retries 3 --host-timeout 5m --script=cups-info,snmp-info,http-title,snmp-sysdescr,sip-methods,nbstat,smb-os-discovery,upnp-info"
    scanner.scan(ip, arguments=nmap_arg)  # -A for OS detection, -O for version detection
    return scanner[ip]

# Function to detect device type based on matching open ports and keywords
def detect_device_type(scan_result):
    device_type_score = defaultdict(int)
    matched_ports = defaultdict(list)
    matched_keywords = defaultdict(list)

    tcp_ports = scan_result.get('tcp', {})
    udp_ports = scan_result.get('udp', {})

    # Step 1: Match open ports with potential device types
    possible_device_types = set()  # Keep track of potential device types

    for device_type, details in DEVICE_TYPE_CATEGORY.items():
        for port in tcp_ports:
            if port in details["tcp_ports"]:
                possible_device_types.add(device_type)
                device_type_score[device_type] += 1
                matched_ports[device_type].append(port)
        for port in udp_ports:
            if port in details["udp_ports"]:
                possible_device_types.add(device_type)
                device_type_score[device_type] += 1
                matched_ports[device_type].append(port)

    # Step 2: Search for keywords in Nmap output, but only for device types matched by ports
    output = str(scan_result)

    for device_type in possible_device_types:
        for keyword in DEVICE_TYPE_CATEGORY[device_type]["keywords"]:
            if re.search(rf'\b{keyword}\b', output, re.IGNORECASE):
                device_type_score[device_type] += 1
                matched_keywords[device_type].append(keyword)

    # Step 3: Print matched keywords and ports
    print("\nDevice Type Detection Details:")
    for device_type in device_type_score:
        print(f"\nDevice Type: {device_type}")
        print(f"Score: {device_type_score[device_type]}")
        print(f"Matched Ports: {matched_ports[device_type]}")
        print(f"Matched Keywords: {matched_keywords[device_type]}")

    # Step 4: Return the device type with the highest score
    if device_type_score:
        return max(device_type_score, key=device_type_score.get)
    else:
        return "Unknown Device Type"

# Main function to run the detection
def main():
    ip_address = input("Enter the IP address to scan: ")
    
    try:
        scan_result = perform_nmap_scan(ip_address)
        device_type = detect_device_type(scan_result)
        print(f"\nFinal Detected Device Type: {device_type}")
    except Exception as e:
        print(f"An error occurred during scanning: {e}")

# Uncomment the following line to run the script
# main()
