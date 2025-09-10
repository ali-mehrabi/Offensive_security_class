import dns.resolver
import dns.query
import dns.zone

def dns_enum(domain, dns_server="8.8.8.8"):
    print(f"[*] DNS enumeration for {domain} using {dns_server}")

    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                print(f"[+] {rtype}: {rdata}")
        except Exception as e:
            print(f"[-] {rtype}: {e}")

    # Try a zone transfer
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns = str(ns)
            try:
                xfr = dns.query.xfr(ns, domain, timeout=3)
                zone = dns.zone.from_xfr(xfr)
                print(f"[!] Zone transfer successful from {ns}")
                for host in zone.nodes.keys():
                    print("   ", host, zone[host].to_text(host))
            except Exception:
                pass
    except:
        pass

# Example:
# dns_enum("example.com")
