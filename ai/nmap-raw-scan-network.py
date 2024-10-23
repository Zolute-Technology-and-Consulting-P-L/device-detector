import os
import subprocess
import re
import json
import netifaces

# File to store scanned MAC addresses (used to resume)
scanned_macs_file = 'scanned_macs.json'

# Function to load scanned MAC addresses
def load_scanned_macs():
    if os.path.exists(scanned_macs_file):
        with open(scanned_macs_file, 'r') as file:
            return set(json.load(file))
    return set()

# Function to save scanned MAC addresses
def save_scanned_macs(scanned_macs):
    with open(scanned_macs_file, 'w') as file:
        json.dump(list(scanned_macs), file)

# Function to detect all interfaces including VLANs
def get_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

# Function to get online hosts on the network for each interface
def get_online_hosts(interface):
    try:
        ip_info = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in ip_info:
            return []

        ip_address = ip_info[netifaces.AF_INET][0]['addr']
        netmask = ip_info[netifaces.AF_INET][0]['netmask']
        network = f"{ip_address}/{netmask}"

        print(f"Scanning network: {network} on interface {interface}")
        
        # Run Nmap ping scan to discover online hosts
        nmap_command = ["nmap", "-sn", network]
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_output = result.stdout.decode('utf-8')

        # Extract live IP addresses
        online_hosts = re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', nmap_output)
        return online_hosts
    except Exception as e:
        print(f"Error detecting hosts on interface {interface}: {e}")
        return []

# Function to clean Nmap output (MAC splitting and whitespace removal)
def clean_nmap_output(nmap_output):
    # Regular expressions to match MAC addresses and whitespace
    mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
    
    # Replace MAC addresses with space-separated values
    def mac_to_spaces(match):
        mac = match.group(0)
        return ' '.join(mac.split(':'))

    cleaned_output = re.sub(mac_pattern, mac_to_spaces, nmap_output)
    
    # Remove extra whitespaces and newlines
    cleaned_output = re.sub(r'\s+', ' ', cleaned_output).strip()
    
    return cleaned_output

# Function to run Nmap scan with provided arguments on each online host
def run_nmap_scan(host_ip, scanned_macs, output_folder):
    # Nmap command with specified arguments
    nmap_command = [
        "nmap", "-sV", "-O", "-sU", "-sS", "-p", "T:1-65535,U:67,68,111,123,137,138,161,162,500,554,631,1701,1812,1813,1900,1935,2049,3702,4500,5004,5005,5060,5061,5353,10000",
        "-T4", "-open", "--min-rate", "300", "--min-parallelism", "50", "--max-retries", "5", "--host-timeout", "10m",
        "--script=rdp-ntlm-info,cups-info,snmp-info,http-title,snmp-sysdescr,sip-methods,nbstat,smb-os-discovery,upnp-info,nbstat,http-server-header,rdp-vuln-ms12-020", host_ip
    ]
    
    # Execute Nmap scan
    result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_raw_output = result.stdout.decode("utf-8")
    
    # Extract MAC address
    mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', nmap_raw_output)
    if not mac_match:
        print(f"Could not find MAC address for host {host_ip}")
        return

    mac_address = mac_match.group(1)
    
    # If this MAC address has already been scanned, skip it
    if mac_address in scanned_macs:
        print(f"MAC {mac_address} already scanned. Skipping.")
        return

    # Clean the raw Nmap output
    cleaned_nmap_output = clean_nmap_output(nmap_raw_output)

    # Save the output to a file named by MAC address (with colons replaced by hyphens)
    filename = f"{mac_address.replace(':', '-')}.txt"
    file_path = os.path.join(output_folder, filename)

    with open(file_path, 'w') as file:
        file.write(cleaned_nmap_output)
    
    print(f"Saved cleaned Nmap output for MAC {mac_address} to {file_path}")

    # Add the MAC address to the set of scanned MACs
    scanned_macs.add(mac_address)
    save_scanned_macs(scanned_macs)

# Main function to detect interfaces, find online hosts, and run Nmap scans
def main():
    output_folder = "./nmap_outputs"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    scanned_macs = load_scanned_macs()

    interfaces = get_interfaces()
    
    for interface in interfaces:
        online_hosts = get_online_hosts(interface)
        for host_ip in online_hosts:
            run_nmap_scan(host_ip, scanned_macs, output_folder)

if __name__ == "__main__":
    main()
