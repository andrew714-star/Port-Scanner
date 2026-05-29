import socket
import threading
import argparse
import sys
import time
from datetime import datetime
from queue import Queue
from typing import Optional


#__ Commen service names________________
SERVICE_NAMES = {
     20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "RPC", 137: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-trap",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-sub", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "OracleDB", 1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker", 3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5000: "Dev-HTTP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis",
    6443: "K8s-API", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "Jupyter", 9200: "Elasticsearch", 9418: "Git",
    27017: "MongoDB", 27018: "MongoDB",
}

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
    111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
    445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1080, 1099, 1194, 1433, 1521, 1720, 1723, 1755,
    1900, 2000, 2001, 2049, 2121, 2181, 2375, 3000, 3128, 3306, 3389,
    3986, 4444, 4899, 5000, 5009, 5051, 5600, 5101, 5190, 5357, 5432, 
    5631, 5666, 5800, 5900, 5985, 5986, 6000, 6001, 6379, 6443, 7070,
    8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9418, 9999, 10000,
    32768, 49152, 27017,

]


#____ Banner grabing____________________________________________________
def grab_banner(host: str, port: int, timeout: float) ->str:
    """Try to grab a service banner frome an open port"""

    try:
        s = socket.socket()
        s.settimeout((timeout))
        s.connect((host, port))
        # Send a HTTP request for web ports
        if port in (80, 8080, 3000, 5000):
            s.send(b"GET / HTTP/1.0\r\nHost " + host.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        #return first nonempty line only
        for line in banner.splitlines():
            line = line.strip()
            if line:
                 return line [:80]
    except Exception:
        pass
    return ""


#___ Scanner worker_________________________________________
class PortScanner:
    def __init__(self, host: str, timeout: float = 1.0, threads: int = 100,
                 banner: bool = False):
        self.host = host
        self.timeout = timeout
        self.threads = threads
        self.grab_banner = banner
        self.open_ports: list[dict] = []
        self._lock = threading.Lock()
        self._queue: Queue = Queue()
        self._scanned = 0
        self._total = 0

    def _resovle(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return None
        
    def _scan_port(self, port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.host, port))
            s.close()

            if result != 0:
                return

            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = SERVICE_NAMES.get(port, "unknown")

            banner = ""
            if self.grab_banner:
                banner = grab_banner(self.host, port, self.timeout)

            with self._lock:
                self.open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                })

        except Exception:
            pass
        finally:
            with self._lock:
                self._scanned += 1

    def _worker(self):
        while True:
            port = self._queue.get()
            if port is None:
                break
            self._scan_port(port)
            self._queue.task_done()

    def scan(self, ports: list[int]) -> list[dict]:
        self._total = len(ports)
        self._scanned = 0
        self.open_ports = []

        for port in ports:
            self._queue.put(port)

        workers = []
        for _ in range(min(self.threads, self._total)):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)



        
           
           
        #___ Progress indicator_________________________   
           
        while not self._queue.empty() or self._scanned < self._total:
            done = self._scanned
            pct = int(done / self._total * 40) if self._total else 40
            bar = "█" * pct + "░" * (40 - pct)
            print(f"\r  [{bar}] {done}/{self._total}", end="", flush=True)
            if done >= self._total:
                break
            time.sleep(0.15)


        self._queue.join()
        for _ in workers:
            self._queue.put(None)
        for t in workers:
            t.join()

        print(f"\r [{'█'*40}] {self._total}/{self._total}", flush=True)
        self.open_ports.sort(key=lambda x: x["port"])
        return self.open_ports

    
    #__ port range parsing ________________________________
def parse_ports(spec: str) -> list[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)

#___ Output formatting___________________________________
def print_results(host: str, ip: str, ports: list[dict], elapsed: float,
                  outfile: Optional[str] = None):
    lines = []
    lines.append(f"\nScan report for {host}" + (f" ({ip})" if ip != host else ""))
    lines.append(f"Scanned at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                 f"- completed in {elapsed:.2f}s")
    lines.append("")

    if not ports:
        lines.append(" No open ports found.")
    else:
        lines.append(f"  {'PORT':<10} {'SERVICE':<18} {'BANNER'}")
        lines.append(" " + "-" * 60)
        for p in ports:
            port_str = f"{p['port']}/tcp"
            banner = p["banner"][:50] if p["banner"] else ""
            lines.append(f". {port_str:<10} {p['service']:<18} {banner}")
        lines.append("")
        lines.append(f"  {len(ports)} open port(s) found.")
    
    output = "\n".join(lines)
    print(output)

    if outfile:
        with open(outfile, "w") as f:
            f.write(output + "\n")
        print(f"\n Results saved to : {outfile}")




#__CLI___________________________________________________________
def main():
    parser = argparse.ArgumentParser(
        description="Fast multithreaded TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("host", help="target host or IP address")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port spec: range (1-1024), list(22,80,443), or single (80). Default:1-1024"
    )
    parser.add_argument(
        "--top100", action="store_true",
        help="Scan the 100 most common ports (overrides -p)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of coucurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-b", "--banner", action="store_true",
        help="Attempt to grab service banners from open ports"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save results to a text file"
    )
    args = parser.parse_args()

    #__ Resolve host_____________________________________-
    print(f"\nResolving {args.host}...")
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror as e:
        print(f" Error: Could not be resolved by host - {e}")
        sys.exit(1)
    print(f" Host: {args.host} → {ip}")

    #__Build port list________________________________________
    if args.top100:
        ports = TOP_100_PORTS
        print(f" Scanning to 100 common ports...")
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print(f" Error: Invalid port specification '{args.ports}'")
            sys.exit(1)
        print(f" Scanning {len(ports)} port(s)...")

    if args.banner:
        print(" Banner grabbing enabled")
    
    print()
    start = time.time()
    scanner = PortScanner(
        host=args.host,
        timeout=args.timeout,
        threads=args.threads,
        banner=args.banner,
    )
    open_ports = scanner.scan(ports)
    elapsed = time.time() - start
    
    print_results(args.host, ip, open_ports, elapsed, args.output)


if __name__ == "__main__":
    main()

