import subprocess
import socket
import os
import platform
import urllib.request
import csv
from io import StringIO

def clear():
    os.system("cls" if os.name == "nt" else "clear")
    

def fetch_common_ports(limit=50):
    url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    try:
        print("🔄 Fetching port list from IANA...")
        response = urllib.request.urlopen(url)
        data = response.read().decode()
        csv_reader = csv.DictReader(StringIO(data))

        ports = {}
        for row in csv_reader:
            if (
                row["Transport Protocol"].lower() == "tcp" and
                row["Port Number"].isdigit() and
                row["Service Name"]
            ):
                port = int(row["Port Number"])
                service = row["Service Name"].strip().lower()

                # Filter only relevant services
                if service in [
				    "ssh", "telnet", "rdp", "vnc", "winrm", "openvpn", "ipsec", "pptp", "kerberos", "radius",
				    "http", "https", "proxy", "webmin", "nginx", "apache", "tomcat", "jetty",
				    "mysql", "mariadb", "postgres", "mssql", "oracle", "redis", "mongodb", "couchdb", "elastic", "zookeeper",
				    "docker", "prometheus", "grafana", "influxdb", "snmp", "syslog", "samba", "smb", "nfs", "rsync", "etcd",
				    "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "ldap", "irc", "jabber"
				]:                    
                    ports[port] = service.upper()

        # Return sorted top ports (by port number)
        return dict(sorted(ports.items())) if ports else fallback_ports()

    except Exception as e:
        print("❌ Failed to fetch port list:", e)
        return fallback_ports()

def fallback_ports():
    return {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MYSQL",
        3389: "RDP"
    }


def get_public_ip():
    try:
        result = subprocess.check_output(["curl", "-s", "https://ipinfo.io/ip"])
        print("🌍 Public IP:", result.decode().strip())
    except Exception as e:
        print("❌ Could not retrieve public IP:", e)

def ping_host():
    host = input("Enter a domain or IP to ping (e.g., 8.8.8.8): ")
    cmd = ["ping", "-c", "4", host] if platform.system() != "Windows" else ["ping", host]
    try:
        subprocess.run(cmd)
    except Exception as e:
        print("❌ Ping failed:", e)

def dns_lookup():
    domain = input("Enter a domain (e.g., google.com): ")
    try:
        ip = socket.gethostbyname(domain)
        print(f"🔎 {domain} resolved to {ip}")
    except Exception as e:
        print("❌ DNS lookup failed:", e)

def scan_ports():
    print("\n🔓 Port Scanner")
    target = input("Enter target IP or domain (e.g., google.com): ").strip()

    common_ports = fetch_common_ports()

    print(f"\nScanning relevant ports on {target}...\n")

    for port, name in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                print(f"✅ Port {port} ({name}) is OPEN")
            else:
                print(f"❌ Port {port} ({name}) is CLOSED")
        except socket.gaierror:
            print("❌ Hostname could not be resolved.")
            break
        except socket.error as e:
            print(f"❌ Socket error on port {port}: {e}")
            break

def traceroute():
    host = input("Enter a domain or IP to trace (e.g. google.com): ").strip()
    system = platform.system()

    print(f"\n🚀 Tracing route to {host}...\n")

    if system == "Windows":
        cmd = ["tracert", host]
    else:
        cmd = ["traceroute", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout

        # Count hops (lines with numbers at start)
        hop_lines = [line for line in output.splitlines() if line.strip().startswith(tuple(str(i) for i in range(1, 50)))]
        print(output)
        print(f"\n📍 Hop Count: {len(hop_lines)} hops")

    except Exception as e:
        print("❌ Traceroute failed:", e)


def show_menu():
    while True:
        clear()
        print("🌐 NETWORK DIAGNOSTIC TOOL")
        print("1. Get Public IP")
        print("2. Ping Host")
        print("3. DNS Lookup")
        print("4. Port Scanner")
        print("5. Traceroute")
        print("6. Exit")
        choice = input("Choose an option [1–4]: ")

        if choice == "1":
            get_public_ip()
        elif choice == "2":
            ping_host()
        elif choice == "3":
            dns_lookup()
        elif choice == "4":
            scan_ports()
        elif choice == "5":
        	traceroute()
        elif choice == "6":
        	print("👋 Goodbye!")
        	break
        else:
            print("Invalid option.")

        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    show_menu()
