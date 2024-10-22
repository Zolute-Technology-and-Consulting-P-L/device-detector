import nmap
import re
import copy
from collections import defaultdict
from device_type_category import DEVICE_TYPE_CATEGORY  # Assuming DEVICE_TYPE_CATEGORY is in the mapping file
from device_type_category import OS_TYPE_CATEGORY  # Assuming OS_TYPE_CATEGORY is in the mapping file

# Function to perform intense scan using nmap
def perform_nmap_scan(ip):
    scanner = nmap.PortScanner()
    print(f"Running intense scan on {ip}...")
    nmap_arg = f"-sV -O -sU -sS -p T:1-65535,U:67,68,111,123,137,138,161,162,500,554,631,1701,1812,1813,1900,1935,2049,3702,4500,5060,5061,5353,10000,16384,32767 -T4 --min-rate 300 --min-parallelism 150 --max-retries 5 --host-timeout 10m --script=rdp-ntlm-info,cups-info,snmp-info,http-title,snmp-sysdescr,sip-methods,nbstat,smb-os-discovery,upnp-info,nbstat,http-server-header,rdp-vuln-ms12-020"
    scanner.scan(ip, arguments=nmap_arg)
    return scanner[ip]

# Function to detect OS family based on matching open ports and keywords
def detect_os_family(scan_result):
    os_family_score = defaultdict(int)
    matched_ports = defaultdict(list)
    matched_keywords = defaultdict(list)

    tcp_ports = scan_result.get('tcp', {})
    udp_ports = scan_result.get('udp', {})

    # Step 1: Match open ports with potential OS families
    possible_os_families = set()

    for os_family, details in OS_TYPE_CATEGORY.items():
        for port in tcp_ports:
            if port in details["tcp_ports"]:
                possible_os_families.add(os_family)
                os_family_score[os_family] += 1
                matched_ports[os_family].append(port)
        for port in udp_ports:
            if port in details["udp_ports"]:
                possible_os_families.add(os_family)
                os_family_score[os_family] += 1
                matched_ports[os_family].append(port)

    # Step 2: Search for keywords in Nmap output, but only for OS families matched by ports
    output = str(scan_result)

    for os_family in possible_os_families:
        for keyword in OS_TYPE_CATEGORY[os_family]["keywords"]:
            # Ensure that only full-word matches are counted
            if re.search(rf'\b{re.escape(keyword)}\b', output, re.IGNORECASE):
                os_family_score[os_family] += 1
                matched_keywords[os_family].append(keyword)

    # Step 3: Print matched keywords and ports
    print("\nOS Family Detection Details:")
    for os_family in os_family_score:
        print(f"\nOS Family: {os_family}")
        print(f"Score: {os_family_score[os_family]}")
        print(f"Matched Ports: {matched_ports[os_family]}")
        print(f"Matched Keywords: {matched_keywords[os_family]}")

    # Step 4: Return the OS family with the highest score
    if os_family_score:
        return max(os_family_score, key=os_family_score.get)
    else:
        return "Unknown OS Family"

# Function to detect device type based on matching open ports and keywords
def detect_device_type(scan_result):
    # Create a deep copy of the scan result
    modified_scan_result = copy.deepcopy(scan_result)

    # Step 1: Remove osmatch where the first osclass has accuracy < 91% from the copied scan result
    if 'osmatch' in modified_scan_result:
        filtered_osmatch = []
        for os_match in modified_scan_result['osmatch']:
            os_classes = os_match.get('osclass', [])
            # Check only the first osclass for accuracy >= 91
            if os_classes and int(os_classes[0].get('accuracy', 0)) >= 91:
                filtered_osmatch.append(os_match)

        modified_scan_result['osmatch'] = filtered_osmatch

        # Debugging output to verify filtering
        print("\nFiltered osmatch (where the first osclass has accuracy >= 91%):")
        for os_match in modified_scan_result['osmatch']:
            first_osclass = os_match['osclass'][0]
            print(f"OS: {os_match['name']}, First OS Class Accuracy: {first_osclass['accuracy']}")
    else:
        print("No osmatch found in the scan result.")

    # Step 2: Initialize device type scores, matched ports, and keywords
    device_type_score = defaultdict(int)
    matched_ports = defaultdict(list)
    matched_keywords = defaultdict(list)

    tcp_ports = scan_result.get('tcp', {})
    udp_ports = scan_result.get('udp', {})

    # Step 3: Match open ports with potential device types
    possible_device_types = set()

    for device_type, details in DEVICE_TYPE_CATEGORY.items():
        for port in tcp_ports:
            if port in details.get("tcp_ports", []):
                possible_device_types.add(device_type)
                device_type_score[device_type] += 1
                matched_ports[device_type].append(port)
        for port in udp_ports:
            if port in details.get("udp_ports", []):
                possible_device_types.add(device_type)
                device_type_score[device_type] += 1
                matched_ports[device_type].append(port)

    # Step 4: Search for keywords in the modified scan result (excluding low-accuracy osmatch)
    print(modified_scan_result)
    output = str(modified_scan_result)

    # Search for keywords in the entire modified scan result for possible device types
    for device_type in possible_device_types:
        for keyword in DEVICE_TYPE_CATEGORY[device_type].get("keywords", []):
            # Ensure that only full-word matches are counted
            if re.search(rf'\b{re.escape(keyword)}\b', output, re.IGNORECASE):
                device_type_score[device_type] += 1
                matched_keywords[device_type].append(keyword)

    # Step 5: Print matched keywords and ports
    print("\nDevice Type Detection Details:")
    for device_type in device_type_score:
        print(f"\nDevice Type: {device_type}")
        print(f"Score: {device_type_score[device_type]}")
        print(f"Matched Ports: {matched_ports[device_type]}")
        if matched_keywords[device_type]:
            print(f"Matched Keywords: {matched_keywords[device_type]}")
        else:
            print("Matched Keywords: None")

    # Step 6: Return the device type with the highest score
    if device_type_score:
        # In case of a tie, this will return one of the highest scoring device types
        return max(device_type_score, key=device_type_score.get)
    else:
        return "Unknown Device Type"

# Function to decide whether to detect OS family based on osmatch accuracy
def should_detect_os_family(scan_result):
    # Check the osmatch section for the highest accuracy
    if 'osmatch' in scan_result:
        highest_accuracy = max([int(os['accuracy']) for os in scan_result['osmatch']])
        print(f"Highest OS Match Accuracy: {highest_accuracy}%")
        # If highest accuracy is 90% or above, trust Nmap's result
        if highest_accuracy >= 90:
            print("OS Match accuracy is 90% or above. Using Nmap's OS match.")
            return False
    return True

# Main function to run both OS family and device type detection
def main():
    ip_address = input("Enter the IP address to scan: ")
    
    try:
        scan_result = perform_nmap_scan(ip_address)
        print(scan_result)

        # Check if we should detect OS family based on osmatch accuracy
        if should_detect_os_family(scan_result):
            os_family = detect_os_family(scan_result)
        else:
            os_family = scan_result['osmatch'][0]['osclass'][0]['osfamily']  # Use the highest osmatch result
        
        device_type = detect_device_type(scan_result)
        os_name = scan_result['osmatch'][0]['name']

        print(f"\nFinal Detected OS Family: {os_family}")
        print(f"\nFinal Detected OS : {os_name}")
        print(f"Final Detected Device Type: {device_type}")
    except Exception as e:
        print(f"An error occurred during scanning: {e}")

# Uncomment the following line to run the script
main()
