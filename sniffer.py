from scapy.all import *
from datetime import datetime
import socket
import ipaddress
import json
import re
import subprocess
import urllib.request
import urllib.error
from collections import Counter

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0

destination_ips = Counter()
applications = Counter()
region_cache = {}
route_cache = {}


def get_service(port):

    common_ports = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Proxy"
    }

    return common_ports.get(port, "Unknown")


def resolve_hostname(ip):

    try:
        return socket.gethostbyaddr(ip)[0]

    except:
        return "Unknown"


def get_region(ip):

    if ip in region_cache:
        return region_cache[ip]

    try:
        address = ipaddress.ip_address(ip)
        if address.is_private or address.is_loopback or address.is_reserved or address.is_multicast:
            region_cache[ip] = "Local Network"
            return region_cache[ip]
    except ValueError:
        region_cache[ip] = "Unknown"
        return region_cache[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8", errors="ignore"))
            if data.get("status") == "success":
                country = data.get("country", "")
                region = data.get("regionName", "")
                city = data.get("city", "")
                parts = [part for part in (city, region, country) if part]
                region_cache[ip] = ", ".join(parts) if parts else "Unknown"
                return region_cache[ip]
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError):
        pass

    region_cache[ip] = "Unknown"
    return region_cache[ip]


def get_network_loop(dest_ip):

    if dest_ip in route_cache:
        return route_cache[dest_ip]

    route_ips = []

    try:
        output = subprocess.check_output(["tracert", "-d", "-h", "10", dest_ip], stderr=subprocess.DEVNULL, text=True, timeout=8)
        for line in output.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                hop_ip = match.group(1)
                if hop_ip not in route_ips:
                    route_ips.append(hop_ip)
    except Exception:
        pass

    route_cache[dest_ip] = route_ips if route_ips else ["Unknown"]
    return route_cache[dest_ip]


def show_insights():

    print("\n================ NETWORK INSIGHTS ================")

    print(f"Total Packets Captured : {packet_count}")
    print(f"TCP Packets            : {tcp_count}")
    print(f"UDP Packets            : {udp_count}")
    print(f"ICMP Packets           : {icmp_count}")

    print("\nTop Destination IPs:")

    for ip, count in destination_ips.most_common(5):
        print(f"{ip} -> {count} packets")

    print("\nMost Used Applications:")

    for app, count in applications.most_common(5):
        print(f"{app} -> {count} packets")

    print("==================================================\n")


def process_packet(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count

    packet_count += 1
    src_ip = None
    dst_ip = None
    protocol_name = "Unknown"
    src_region = "Unknown"
    dst_region = "Unknown"
    source_port = "N/A"
    destination_port = "N/A"
    route_ips = []

    print("\n===================================================")
    print("                 PACKET CAPTURED")
    print("===================================================")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Time               : {timestamp}")
    print(f"Packet Size        : {len(packet)} bytes")

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        destination_ips[dst_ip] += 1

        protocol = packet[IP].proto

        print(f"Source IP          : {src_ip}")
        print(f"Destination IP     : {dst_ip}")

        src_host = resolve_hostname(src_ip)
        dst_host = resolve_hostname(dst_ip)

        print(f"Source Host        : {src_host}")
        print(f"Destination Host   : {dst_host}")

        src_region = get_region(src_ip)
        dst_region = get_region(dst_ip)
        print(f"Source Region      : {src_region}")
        print(f"Destination Region : {dst_region}")

        route_ips = get_network_loop(dst_ip)
        print(f"Network Loop       : {', '.join(route_ips)}")

        if protocol == 6:

            protocol_name = "TCP"
            tcp_count += 1

        elif protocol == 17:

            protocol_name = "UDP"
            udp_count += 1

        elif protocol == 1:

            protocol_name = "ICMP"
            icmp_count += 1

        else:

            protocol_name = str(protocol)

        print(f"Protocol           : {protocol_name}")

    app_name = "Unknown"

    if packet.haslayer(TCP):

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        print(f"Source Port        : {source_port}")
        print(f"Destination Port   : {destination_port}")

        app_name = get_service(destination_port)

        print(f"Application        : {app_name}")

    elif packet.haslayer(UDP):

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        print(f"Source Port        : {source_port}")
        print(f"Destination Port   : {destination_port}")

        app_name = get_service(destination_port)

        print(f"Application        : {app_name}")

        sport = packet[UDP].sport
        dport = packet[UDP].dport

        print(f"Source Port        : {sport}")
        print(f"Destination Port   : {dport}")

        app_name = get_service(dport)

        print(f"Application        : {app_name}")

    applications[app_name] += 1

    if packet.haslayer(Raw):

        try:

            payload = packet[Raw].load.decode(errors="ignore")

            print("\nPayload Preview:")
            print(payload[:200])

        except:
            pass

    if len(packet) > 1500:

        print("\n[!] ALERT: Large packet detected")

    if app_name == "Unknown":

        print("\n[!] Warning: Unknown application traffic")

    print("\nPacket Summary:")
    print(packet.summary())

    with open("captured_packets.txt", "a", encoding="utf-8") as file:

        file.write("\n===================================================\n")
        file.write(f"Time: {timestamp}\n")

        if packet.haslayer(IP):

            file.write(f"Source IP: {src_ip}\n")
            file.write(f"Destination IP: {dst_ip}\n")
            file.write(f"Protocol: {protocol_name}\n")
            file.write(f"Source Region: {src_region}\n")
            file.write(f"Destination Region: {dst_region}\n")
            file.write(f"Network Loop: {', '.join(route_ips)}\n")

        if source_port != "N/A":
            file.write(f"Source Port: {source_port}\n")
            file.write(f"Destination Port: {destination_port}\n")

        file.write(packet.summary() + "\n")

    if packet_count % 10 == 0:

        show_insights()


print("\nNetwork Sniffer Started...")
print("Capturing Live Traffic...")
print("Detailed Insights will appear every 10 packets.")
print("Press CTRL + C to stop.\n")

sniff(prn=process_packet, store=False)