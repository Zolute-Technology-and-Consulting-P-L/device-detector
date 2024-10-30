import os
import re
import subprocess
import xml.etree.ElementTree as ET

# Function to clean Nmap output and split MAC address by spaces
def clean_nmap_output(nmap_output):
    # Regular expressions to match IP addresses and MAC addresses
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')  # Matches IPv4 addresses
    mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')  # Matches MAC addresses
    
    # Remove IP addresses
    cleaned_output = re.sub(ip_pattern, '[REDACTED_IP]', nmap_output)
    
    # Replace MAC addresses with space-separated values
    def mac_to_spaces(match):
        mac = match.group(0)
        return ' '.join(mac.split(':'))  # Replace colon with space in MAC address

    cleaned_output = re.sub(mac_pattern, mac_to_spaces, cleaned_output)
    
    # Remove extra whitespaces, newlines, and unnecessary characters
    cleaned_output = re.sub(r'\s+', ' ', cleaned_output).strip()
    
    return cleaned_output

# Function to run the Nmap scan and save raw output by MAC address
def scan_and_save_by_mac(subnet, output_folder):
    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Run the Nmap command
    nmap_command = [
        "nmap", "-sP", "-oX", "-",  # Nmap ping scan with XML output
        subnet
    ]
    
    # Execute the Nmap command and capture XML output
    result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output_xml = result.stdout.decode("utf-8")
    
    # Parse the XML output using ElementTree
    root = ET.fromstring(nmap_output_xml)
    
    # Iterate through hosts in the Nmap result
    for host in root.findall('host'):
        # Extract the MAC address and the IP address
        address_elements = host.findall('address')
        mac_address = None
        ip_address = None
        
        for addr in address_elements:
            if addr.get('addrtype') == 'mac':
                mac_address = addr.get('addr')
            elif addr.get('addrtype') == 'ipv4':
                ip_address = addr.get('addr')
        
        # If a MAC address is found, save the raw Nmap output for that host
        if mac_address:
            # Run a full Nmap scan for this specific host
            nmap_command_for_host = [
                "nmap", "-F", "-sS", "-sU", "-O", "-n", "--script=rdp-ntlm-info,snmp-info,http-title,"
                "snmp-sysdescr,sip-methods,nbstat,smb-os-discovery,upnp-info,nbstat,http-server-header,"
                "rdp-vuln-ms12-020,bacnet-info,omron-info,pcworx-info,modbus-discover,s7-info,enip-info,hnap-info",
                "-oN", "-",  # Save output as raw text (-oN)
                ip_address
            ]
            
            # Execute the Nmap scan for this host
            result_host = subprocess.run(nmap_command_for_host, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            nmap_raw_output = result_host.stdout.decode("utf-8")
            
            # Clean the raw Nmap output
            cleaned_nmap_output = clean_nmap_output(nmap_raw_output)
            
            # Create the filename based on MAC address and save the cleaned output
            filename = f"{mac_address.replace(':', '-')}.txt"
            file_path = os.path.join(output_folder, filename)
            
            with open(file_path, "w") as file:
                file.write(cleaned_nmap_output)
            
            print(f"Saved cleaned Nmap output for MAC {mac_address} to {file_path}")
        else:
            print(f"No MAC address found for IP {ip_address}")

# Example usage
subnet = "192.168.1.0/24"  # Subnet to scan
output_folder = "/path/to/output/folder"  # Folder to save the Nmap output files

scan_and_save_by_mac(subnet, output_folder)
