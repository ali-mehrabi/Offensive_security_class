'''
Crafts a NetBIOS name query packet (* wildcard query).
Sends it to UDP/137 on the target.
Parses the response to show NetBIOS name information (hostname, workgroup, etc.).
'''

from scapy.all import *
import sys

def netbios_enum(target_ip):
    # NetBIOS Name Service query packet
    name_query = (
        b'\x81\x00'              # Transaction ID
        b'\x00\x10'              # Flags (query)
        b'\x00\x01'              # Questions: 1
        b'\x00\x00'              # Answer RRs: 0
        b'\x00\x00'              # Authority RRs: 0
        b'\x00\x00'              # Additional RRs: 0
        b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'  # Query name (* wildcard)
        b'\x00\x21'              # Type: NB (0x21)
        b'\x00\x01'              # Class: IN
    )

    print(f"[*] Sending NetBIOS Name Service query to {target_ip}")

    resp = sr1(IP(dst=target_ip)/UDP(dport=137)/Raw(load=name_query), timeout=2, verbose=0)

    if resp and resp.haslayer(Raw):
        data = resp[Raw].load
        print("[+] Received NetBIOS Response")
        try:
            # Extract ASCII strings from response for readable output
            ascii_strings = ''.join([chr(b) if 32 <= b < 127 else '.' for b in data])
            print(ascii_strings)
        except Exception as e:
            print("[-] Error parsing response:", e)
    else:
        print("[-] No response or host not vulnerable")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: sudo python {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    netbios_enum(target)
