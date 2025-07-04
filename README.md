# Subdomain Recon Tool

A powerful, multi-phase subdomain discovery tool that combines certificate transparency scraping, ASN netblock mapping, and multi-threaded reverse DNS scanning.

## 🔍 Features

- ✅ Extracts subdomains from **crt.sh** (certificate transparency logs)
- ✅ Automatically fetches **ASN** from domain WHOIS
- ✅ Queries **RADB** for netblocks tied to the ASN
- ✅ Performs multi-threaded **reverse DNS** scans on those IP ranges
- ✅ Outputs all unique subdomains to a file

---

## 🚀 Usage

```bash
python3 subdomain_recon.py <target-domain>
```

Example:
```
python3 subdomain_recon.py example.com
```
Output will be saved to:

`subdomains-example.com.txt`

---

## 📦 Requirements

Python 3

requests module:
```
pip install requests
```
Linux/macOS with:

`whois command-line tool installed`

---

## 🧠 How It Works

1. crt.sh is queried for any TLS certificate ever issued to *.domain.com

2. A WHOIS lookup is used to identify the ASN associated with the domain

3. RADB is queried to find all IP ranges registered to that ASN

4. A subset of those IPs is scanned with reverse DNS lookups

5. Subdomains matching the target domain are extracted and stored

---

## 🛡️ Disclaimer

This tool is intended for educational and authorized security research purposes only. Do not use it on domains or networks you don't own or have permission to test.

---

## 💡 Ideas for Future Versions

Add DNS wordlist brute-forcing

Integrate with Shodan/Censys APIs

Monitor subdomain changes over time

Export results to JSON or HTML reports

---

## 🧑‍💻 Author

Built by illdeed. 
Contributions welcome — open an issue or PR!
