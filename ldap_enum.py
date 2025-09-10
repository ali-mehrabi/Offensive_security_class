from ldap3 import Server, Connection, ALL

def ldap_enum(target, base_dn, user="", password=""):
    print(f"[*] LDAP enumeration on {target}")

    try:
        server = Server(target, get_info=ALL)
        conn = Connection(server, user=user, password=password, auto_bind=True)

        conn.search(base_dn, "(objectClass=*)", attributes=["cn", "sAMAccountName"])
        for entry in conn.entries:
            print(f"[+] {entry}")

        conn.unbind()
    except Exception as e:
        print(f"[-] LDAP error: {e}")

# Example:
# ldap_enum("192.168.1.20", "dc=example,dc=com")
