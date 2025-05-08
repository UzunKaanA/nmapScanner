#!/usr/bin/env python3
import nmap
import ipaddress
import re
import pyfiglet

banner = pyfiglet.figlet_format("Kaan  A.  UZUN")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535

print(banner)

print("\n****************************************************************")
print("\n* https://www.uzunkaan.website                                 *")
print("\n* https://www.linkedin.com/in/uzunkaana/                       *")
print("\n* https://github.com/UzunKaanA                                 *")
print("\n* https://medium.com/@27uzunkaan                               *")
print("\n****************************************************************")


while True:
    ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
    # If we enter an invalid ip address the try except block will go to the except block and say you entered an invalid ip address.
    try:
        ip_address_obj = ipaddress.ip_address(ip_add_entered)
        # The following line will only execute if the ip is valid.
        print("You entered a valid ip address.")
        break
    except:
        print("You entered an invalid ip address")
        
nm = nmap.PortScanner()
print("State: Scanning... Option: nmap -sV -sC -T4 " f"{ip_add_entered}")

try:
    result = nm.scan(ip_add_entered, arguments="-sV -sC -T4")

    # Extract open ports and their details
    for proto in nm[ip_add_entered].all_protocols():
        ports = nm[ip_add_entered][proto].keys()
        for port in ports:
            port_info = nm[ip_add_entered][proto][port]
            state = port_info.get('state', 'unknown')
            if state == 'open':
                name = port_info.get('name', 'unknown')
                product = port_info.get('product', 'unknown')
                version = port_info.get('version', 'unknown')
                extrainfo = port_info.get('extrainfo', 'unknown')
                reason = port_info.get('reason', 'unknown')
                conf = port_info.get('conf', 'unknown')
                cpe = port_info.get('cpe', 'unknown')
                
                print(f"\nPort: {port} ({proto})")
                print(f"  State      : open")
                print(f"  Service    : {name}")
                print(f"  Product    : {product}")
                print(f"  Version    : {version}")
                print(f"  Extra Info : {extrainfo}")
                print(f"  Reason     : {reason}")
                print(f"  Conf       : {conf}")
                print(f"  CPE        : {cpe}")

except Exception as e:
    print("An error occurred during the scan:", str(e))