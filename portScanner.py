#PortScanner
from scapy.all import *
import re

try:
    host = input("Enter a host address: ")
    ports = list(map(int, input("Enter the ports to scan (comma-separated): ").split(",")))

    if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        print("\n\nScanning...")
        print("Host: ", host)
        print("Ports: ", ports)

        # Send SYN packets to specified ports and wait for responses
        ans, unans = sr(IP(dst=host) / TCP(dport=ports, flags="S"), verbose=0, timeout=2)

        # Process responses
        for pkt in ans:
            s_port = pkt[0][TCP].sport
            print(f"[+] Port {s_port} is open")

except (ValueError, RuntimeError, TypeError, NameError) as e:
    print("[-] Some Error Occurred:", e)

print("[-] Exiting..")
