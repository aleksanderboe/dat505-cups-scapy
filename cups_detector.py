import argparse
import csv
import ipaddress
import json
import re
import sys
from datetime import datetime

from scapy.all import rdpcap, sniff, IP, UDP, TCP, Raw


# RFC1918 + loopback + link-local
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Direct signature patterns (CVE-2024-47076 / 47175)
SIGNATURES = [
    (rb"FoomaticRIPCommandLine",      "PPD injection directive (CVE-2024-47177)"),
    (rb"cupsFilter2",                 "PPD filter injection directive"),
    (rb"printer-privacy-policy-uri",  "Known injection attribute name"),
    (rb"\\n\*",                       "Escaped newline + PPD directive"),
]

URI_RE = re.compile(rb'(?:ipp|http|https)://([^/"\s]+)')


def is_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in PRIVATE_NETS)


class Detector:
    def __init__(self, allowlist=None):
        self.allowlist = set(allowlist or [])
        self.alerts = []
        self.browse_counter = {}  # src_ip -> [timestamps]

    def _alert(self, severity, rule, src, dst, detail, packet_info=None):
        self.alerts.append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "severity": severity,
            "rule": rule,
            "src": src,
            "dst": dst,
            "detail": detail,
            "packet": packet_info or {},
        })
        print(f"[{severity}] {rule}: {src} -> {dst} | {detail}")

    def analyze(self, pkt):
        if not pkt.haslayer(IP):
            return

        # ---------- UDP/631: CUPS browse announcements ----------
        if pkt.haslayer(UDP) and pkt[UDP].dport == 631:
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            src, dst = pkt[IP].src, pkt[IP].dst

            # Rule 1: external source
            if not is_private(src):
                self._alert("HIGH", "UDP631_EXTERNAL_SOURCE", src, dst,
                            "Browse packet from non-private source")

            # Rule 2: suspicious URI in browse packet
            for m in URI_RE.finditer(payload):
                host = m.group(1).decode(errors="ignore").split(":")[0]
                if host and host not in self.allowlist and not is_private(host):
                    self._alert("HIGH", "UDP631_UNKNOWN_URI", src, dst,
                                f"Browse packet advertises non-allowlisted URI host '{host}'")

            # Rule 3: signature match in browse packet
            for pat, desc in SIGNATURES:
                if re.search(pat, payload, re.IGNORECASE):
                    self._alert("CRITICAL", "UDP631_PPD_INJECTION", src, dst,
                                f"Browse payload contains {desc}")

            # Rule 4: rate anomaly (>=5 packets in 10 s)
            import time
            now = time.time()
            hist = self.browse_counter.setdefault(src, [])
            hist.append(now)
            hist[:] = [t for t in hist if now - t <= 10]
            if len(hist) >= 5:
                self._alert("MEDIUM", "UDP631_RATE_ANOMALY", src, dst,
                            f"{len(hist)} browse packets from {src} in 10s")

        # ---------- TCP/8631 or any outbound IPP: reverse connections ----------
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            src, dst = pkt[IP].src, pkt[IP].dst
            sport, dport = pkt[TCP].sport, pkt[TCP].dport

            # Only care about traffic *to* IPP-ish ports (631, 8631, custom)
            if dport in (631, 8631) or sport in (631, 8631):
                for pat, desc in SIGNATURES:
                    if re.search(pat, payload, re.IGNORECASE):
                        self._alert("CRITICAL", "IPP_PPD_INJECTION", src, dst,
                                    f"IPP traffic contains {desc} (TCP {sport}->{dport})")

    def export_csv(self, path):
        if not self.alerts:
            print(f"[!] No alerts to write to {path}")
            return
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self.alerts[0].keys())
            w.writeheader()
            w.writerows(self.alerts)
        print(f"[+] Wrote {len(self.alerts)} alerts to {path}")

    def export_json(self, path):
        with open(path, "w") as f:
            json.dump(self.alerts, f, indent=2)
        print(f"[+] Wrote {len(self.alerts)} alerts to {path}")


def main():
    parser = argparse.ArgumentParser(description="CUPS discovery detector")
    parser.add_argument("--pcap", metavar="FILE", help="Analyze a pcap file")
    parser.add_argument("--live", action="store_true", help="Live capture")
    parser.add_argument("--iface", default="en0", help="Interface for live mode")
    parser.add_argument("--csv", metavar="FILE", help="Write alerts to CSV")
    parser.add_argument("--json", metavar="FILE", help="Write alerts to JSON")
    parser.add_argument("--allowlist", metavar="FILE",
                        help="File with allowed printer hosts (one per line)")
    args = parser.parse_args()

    allowlist = []
    if args.allowlist:
        with open(args.allowlist) as f:
            allowlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    detector = Detector(allowlist=allowlist)

    if args.pcap:
        print(f"[*] Analyzing {args.pcap}")
        pkts = rdpcap(args.pcap)
        for p in pkts:
            detector.analyze(p)
    elif args.live:
        print(f"[*] Live capture on {args.iface} (Ctrl-C to stop)")
        sniff(iface=args.iface,
              filter="udp port 631 or tcp port 631 or tcp port 8631",
              prn=detector.analyze, store=0)
    else:
        parser.print_help()
        return

    if args.csv:
        detector.export_csv(args.csv)
    if args.json:
        detector.export_json(args.json)

    print(f"\n[*] Total alerts: {len(detector.alerts)}")


if __name__ == "__main__":
    main()