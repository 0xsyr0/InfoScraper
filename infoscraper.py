#!/usr/bin/env python3

import argparse
import requests
import re
import sys
import pyfiglet
from termcolor import colored

def display_banner():
    banner = pyfiglet.figlet_format("InfoScraper", font="digital")
    print(colored(banner, "cyan"), flush=True)

def scan_content(content):
    results = {}
    for name, pattern in patterns.items():
        matches = pattern.findall(content)
        if matches:
            results[name] = list(set(matches))
    return results

def extract_wordlist(content):
    words = re.findall(r"[a-zA-Z_\-]+", content)
    unique_sorted = sorted(set(words))
    return unique_sorted

def analyze_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.ConnectionError:
        print(f"[x] Could not connect to {url}. Is the target running or reachable?")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[x] An error occurred: {e}")
        return None

patterns = {
    "credentials": re.compile(r'(?:password|pass|token|secret|api[-_]?key|auth|credential|private[-_]key)[\s:=]+["\']?([A-Za-z0-9@#\$%^&+=!_-]+)["\']?', re.IGNORECASE),
    "jwt": re.compile(r'(eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,})'),
    "ips": re.compile(r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
    "awsKeys": re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    "emails": re.compile(r'([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)', re.IGNORECASE),
    "urlSecrets": re.compile(r'(https?:\/\/[^:\/]+:[^@\/]+@)')
}

parser = argparse.ArgumentParser(description="InfoScraper - Extract secrets and/or wordlists from a target URL.")
parser.add_argument("-u", "--url", help="Target URL to scan", type=str)
parser.add_argument("-s", "--secrets", help="Scan for secrets in page content", action="store_true")
parser.add_argument("-w", "--wordlist", help="Generate a wordlist from the page content", action="store_true")
parser.add_argument("-o", "--output", help="Output file to save results (optional for both modes)", type=str)

if len(sys.argv) == 1:
    display_banner()
    parser.print_help()
    sys.exit(0)

try:
    display_banner()
    args = parser.parse_args()

    if not args.url:
        print("[x] You must provide a URL using -u.")
        sys.exit(1)

    if not args.secrets and not args.wordlist:
        print("[x] Please specify a mode: use -s for secret scanning and/or -w for wordlist generation.")
        sys.exit(1)

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        print("[x] Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    content = analyze_url(url)
    if content is None:
        print("[x] No content retrieved.")
        sys.exit(1)

    output_lines = []

    if args.secrets:
        secrets = scan_content(content)
        if secrets:
            output_lines.append("[!] Potential secrets found:\n")
            for category, values in secrets.items():
                output_lines.append(f"{category.upper()}")
                for value in values:
                    output_lines.append(f"  - {value}")
            output_lines.append("")
        else:
            output_lines.append("[-] No secrets found.\n")

    if args.wordlist:
        wordlist = extract_wordlist(content)
        output_lines.append(f"[+] Wordlist ({len(wordlist)} words):\n")
        output_lines.extend(wordlist)
        output_lines.append("")

    print("\n" + "\n".join(output_lines))

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write("\n".join(output_lines) + "\n")
            print(f"\n[+] Results saved to: {args.output}")
        except Exception as e:
            print(f"[x] Failed to save to {args.output}: {e}")

except KeyboardInterrupt:
    print("\n[!] Exiting...")
    sys.exit(130)
