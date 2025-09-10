#performs a SYNC scan on a target IP showing open/closed/filterd ports
from scapy.all import IP, TCP, sr1, conf
import sys

def syn_scan(target_ip, ports):
    conf.verb = 0  # disable verbose Scapy output
    print(f"[*] Starting SYN scan on {target_ip}")

    for port in ports:
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1)

        if resp is None:
            print(f"Port {port}: Closed/Filtered")
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN+ACK → open
                print(f"Port {port}: Open")
                # send RST to close the connection
                rst_pkt = IP(dst=target_ip)/TCP(dport=port, flags="R")
                sr1(rst_pkt, timeout=1)
            elif resp[TCP].flags == 0x14:  # RST → closed
                print(f"Port {port}: Closed")
        else:
            print(f"Port {port}: Closed/Filtered")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    ports_to_scan = range(20, 1025)  # scan common ports
    syn_scan(target, ports_to_scan)
