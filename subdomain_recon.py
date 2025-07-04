#!/usr/bin/env python3

import subprocess
import requests
import socket
import re
import ipaddress
import sys
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 50
IP_LIMIT_PER_BLOCK = 256

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        print("[*] Querying crt.sh...")
        response = requests.get(url, timeout=10)
        data = response.json()
        entries = {item["name_value"] for item in data}
        results = set()
        for entry in entries:
            for line in entry.splitlines():
                if domain in line:
                    results.add(line.strip())
        return sorted(results)
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []

def get_asn(domain):
    try:
        print("[*] Running whois to get ASN...")
        output = subprocess.check_output(["whois", domain], text=True)
        match = re.search(r'origin:\s*(AS\d+)', output)
        return match.group(1) if match else None
    except Exception as e:
        print(f"[!] ASN whois error: {e}")
        return None

def get_netblocks_from_asn(asn):
    try:
        print(f"[*] Getting netblocks for {asn}...")
        output = subprocess.check_output(["whois", "-h", "whois.radb.net", f"-i origin {asn}"], text=True)
        blocks = re.findall(r'route:\s+([\d\.\/]+)', output)
        return list(set(blocks))
    except Exception as e:
        print(f"[!] RADB query error: {e}")
        return []

def expand_cidr(cidr, limit=IP_LIMIT_PER_BLOCK):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net][:limit]
    except Exception:
        return []

def reverse_dns(ip, target_domain):
    try:
        host = socket.gethostbyaddr(ip)[0]
        if target_domain in host:
            return host
    except:
        return None

def reverse_dns_sweep(blocks, target_domain):
    found = set()
    ips_to_scan = []
    for block in blocks[:3]:  # limit to 3 netblocks
        print(f"[*] Expanding block {block}")
        ips = expand_cidr(block)
        ips_to_scan.extend(ips)

    print(f"[*] Starting multi-threaded reverse DNS on {len(ips_to_scan)} IPs...")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(reverse_dns, ip, target_domain): ip for ip in ips_to_scan}
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] Reverse DNS match: {result}")
                found.add(result)

    return found

def write_to_file(domain, subdomains):
    filename = f"subdomains-{domain}.txt"
    with open(filename, "w") as f:
        for sub in sorted(subdomains):
            f.write(sub + "\n")
    print(f"[✓] Output written to: {filename}")

def main(domain):
    print(f"[+] Starting recon on: {domain}\n")
    all_subs = set()

    crt_subs = get_subdomains_crtsh(domain)
    print(f"[+] {len(crt_subs)} subdomains from crt.sh")
    all_subs.update(crt_subs)

    asn = get_asn(domain)
    if asn:
        print(f"[+] ASN: {asn}")
        blocks = get_netblocks_from_asn(asn)
        print(f"[+] {len(blocks)} netblocks found")
        rev_subs = reverse_dns_sweep(blocks, domain)
        print(f"[+] {len(rev_subs)} subdomains from reverse DNS")
        all_subs.update(rev_subs)
    else:
        print("[!] ASN not found – skipping IP-based recon")

    print(f"\n[✓] Recon complete. Total unique subdomains found: {len(all_subs)}")
    write_to_file(domain, all_subs)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain_recon.py <domain>")
        sys.exit(1)
    main(sys.argv[1])#!/usr/bin/env python3

import subprocess
import requests
import socket
import re
import ipaddress
import sys
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 50
IP_LIMIT_PER_BLOCK = 256

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        print("[*] Querying crt.sh...")
        response = requests.get(url, timeout=10)
        data = response.json()
        entries = {item["name_value"] for item in data}
        results = set()
        for entry in entries:
            for line in entry.splitlines():
                if domain in line:
                    results.add(line.strip())
        return sorted(results)
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []

def get_asn(domain):
    try:
        print("[*] Running whois to get ASN...")
        output = subprocess.check_output(["whois", domain], text=True)
        match = re.search(r'origin:\s*(AS\d+)', output)
        return match.group(1) if match else None
    except Exception as e:
        print(f"[!] ASN whois error: {e}")
        return None

def get_netblocks_from_asn(asn):
    try:
        print(f"[*] Getting netblocks for {asn}...")
        output = subprocess.check_output(["whois", "-h", "whois.radb.net", f"-i origin {asn}"], text=True)
        blocks = re.findall(r'route:\s+([\d\.\/]+)', output)
        return list(set(blocks))
    except Exception as e:
        print(f"[!] RADB query error: {e}")
        return []

def expand_cidr(cidr, limit=IP_LIMIT_PER_BLOCK):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net][:limit]
    except Exception:
        return []

def reverse_dns(ip, target_domain):
    try:
        host = socket.gethostbyaddr(ip)[0]
        if target_domain in host:
            return host
    except:
        return None

def reverse_dns_sweep(blocks, target_domain):
    found = set()
    ips_to_scan = []
    for block in blocks[:3]:  # limit to 3 netblocks
        print(f"[*] Expanding block {block}")
        ips = expand_cidr(block)
        ips_to_scan.extend(ips)

    print(f"[*] Starting multi-threaded reverse DNS on {len(ips_to_scan)} IPs...")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(reverse_dns, ip, target_domain): ip for ip in ips_to_scan}
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] Reverse DNS match: {result}")
                found.add(result)

    return found

def write_to_file(domain, subdomains):
    filename = f"subdomains-{domain}.txt"
    with open(filename, "w") as f:
        for sub in sorted(subdomains):
            f.write(sub + "\n")
    print(f"[✓] Output written to: {filename}")

def main(domain):
    print(f"[+] Starting recon on: {domain}\n")
    all_subs = set()

    crt_subs = get_subdomains_crtsh(domain)
    print(f"[+] {len(crt_subs)} subdomains from crt.sh")
    all_subs.update(crt_subs)

    asn = get_asn(domain)
    if asn:
        print(f"[+] ASN: {asn}")
        blocks = get_netblocks_from_asn(asn)
        print(f"[+] {len(blocks)} netblocks found")
        rev_subs = reverse_dns_sweep(blocks, domain)
        print(f"[+] {len(rev_subs)} subdomains from reverse DNS")
        all_subs.update(rev_subs)
    else:
        print("[!] ASN not found – skipping IP-based recon")

    print(f"\n[✓] Recon complete. Total unique subdomains found: {len(all_subs)}")
    write_to_file(domain, all_subs)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain_recon.py <domain>")
        sys.exit(1)
    main(sys.argv[1])
