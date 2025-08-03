import requests
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller
import time
import random
import re
import json
import argparse

# --- Tor Configuration ---
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051

# --- User-Agent Rotation ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1"
]

# requests session for persistence and proxy settings
session = requests.session()
session.proxies = {
    'http': f'socks5h://127.0.0.1:{TOR_SOCKS_PORT}',
    'https': f'socks5h://127.0.0.1:{TOR_SOCKS_PORT}'
}

# --- IP Rotation and IP Fetching Functions (Simplified for Anonsurf) ---

def renew_tor_ip():
    """
    Renews the Tor IP address by sending a NEWNYM signal to the Tor Control Port.
    """
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            print("[+] Tor IP successfully renewed.")
            time.sleep(random.uniform(5, 10))
    except Exception as e:
        print(f"[-] Error renewing Tor IP: {e}. If this persists, you might need to manually set a ControlPort password in torrc.")

def get_current_ip():
    """
    Fetches the current public IP address through the Tor SOCKS5 proxy.
    """
    try:
        response = session.get("http://httpbin.org/ip", timeout=30)
        return response.json().get('origin')
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching current IP: {e}")
        return None

# --- IMPORTANT: ADD YOUR CAPTURED COOKIE HERE ---
# Replace 'your_cookie_name' and 'your_cookie_value' with the actual
# name and value you captured from Tor Browser's developer tools.
# Note: This is a temporary solution as cookies can expire.
SCOOPED_COOKIES = {
    'dread': 'cuggj7vflt1kinq51ve2f50jp6v'
}

def scrape_onion_url(url):
    """
    Fetches content from a given .onion URL, parses it, and extracts data.
    Implements error handling, User-Agent rotation, and uses a hardcoded cookie.
    """
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://www.google.com/',
        'DNT': '1',
        'Connection': 'keep-alive'
    }

    print(f"[*] Attempting to fetch: {url}")
    try:
        # Pass the cookies with the request
        response = session.get(url, headers=headers, cookies=SCOOPED_COOKIES, timeout=240)
        response.raise_for_status()

        # Check if the waiting room text is still in the response
        if "Your estimated wait time is" in response.text:
            print(f"    [!] Detected waiting room on {url}. The cookie may be expired or incorrect.")
            return None # The cookie didn't work, so we stop and return nothing
            
        print(f"[+] Successfully fetched {url}. Status: {response.status_code}")
        soup = BeautifulSoup(response.content, 'html.parser')

        # --- DATA EXTRACTION LOGIC (THIS IS SITE-SPECIFIC!) ---
        extracted_items = []
        posts = soup.find_all('div', class_='forum-post-container')

        if not posts:
            print("    [!] No specific forum posts found (check HTML structure). Attempting general text extraction.")
            paragraphs = soup.find_all('p')
            for p in paragraphs[:10]:
                text = p.get_text(strip=True)
                if text:
                    extracted_items.append({'url': url, 'type': 'general_paragraph', 'content': text[:500] + ('...' if len(text) > 500 else '')})
                    print(f"    - General Text: {text[:70]}...")

        for post in posts:
            title_tag = post.find('h3', class_='post-title')
            content_tag = post.find('div', class_='post-body')
            author_tag = post.find('span', class_='post-author')

            title = title_tag.get_text(strip=True) if title_tag else "N/A"
            content = content_tag.get_text(strip=True) if content_tag else "N/A"
            author = author_tag.get_text(strip=True) if author_tag else "N/A"

            content = re.sub(r'\s+', ' ', content).strip()

            # ... (Your comprehensive keyword lists here) ...
            keywords_basic = ["malware", "ransomware", "phishing", "spoofing", "botnet", "DDoS", "exploit", "vulnerability", "brute force", "keylogger", "spyware", "trojan", "worm", "backdoor", "data breach", "data exfiltration", "credential theft", "social engineering", "unauthorized access", "network intrusion", "firewall bypass", "encryption bypass", "packet sniffing", "rootkit", "shellcode", "payload", "command and control", "dark web", "deep web", "underground forum", "black hat", "threat actor"]
            keywords_ai_ml = ["wormgpt", "fraudgpt", "evilgpt", "ai malware", "ai phishing", "llm exploit", "generative ai cyber", "ai-driven attack", "adversarial AI", "model poisoning", "data poisoning", "model evasion", "deepfake", "synthetic data attack", "AI-powered social engineering", "AI-generated content", "AI model theft", "AI bias injection", "machine learning exploit", "AI security risk", "AI vulnerability", "AI-enhanced malware", "LLM security", "AI red teaming"]
            keywords_cloud = ["aws s3", "azure ad", "kubernetes exploit", "cloud misconfiguration", "iam bypass", "gcp exploit", "cloud breach", "serverless hack", "cloud security posture", "container escape", "docker exploit", "kubernetes vulnerability", "cloud native attack", "API security flaw", "serverless vulnerability", "SaaS compromise", "IaaS breach", "PaaS vulnerability", "cloud identity compromise", "storage bucket expose", "cloud access key leak", "cloud privilege escalation", "shadow IT cloud", "cloud data exfiltration", "multi-cloud security", "cloud network segmentation"]
            keywords_ransomware = ["ransomware attack", "data encryption", "double extortion", "ransom note", "decryption key", "Ransomware-as-a-Service", "Ryuk", "Maze", "REvil", "DarkSide", "WannaCry", "NotPetya", "Conti", "LockBit", "Clop", "Hive"]
            keywords_phishing_social_eng = ["spear phishing", "whaling", "smishing", "vishing", "business email compromise", "email compromise", "credential harvesting", "typosquatting", "domain spoofing", "look-alike domain", "malicious link", "malicious attachment", "pretexting", "baiting", "quid pro quo"]
            keywords_zero_day_exploit = ["zero-day vulnerability", "zero-day exploit", "unpatched vulnerability", "n-day exploit", "vulnerability disclosure", "proof-of-concept", "remote code execution", "privilege escalation", "memory corruption", "buffer overflow", "SQL injection", "cross-site scripting", "deserialization vulnerability", "log4j exploit"]
            keywords_supply_chain = ["supply chain compromise", "software supply chain attack", "third-party risk", "dependency confusion", "software integrity", "code tampering", "package manager exploit", "SolarWinds", "3CX attack", "XZ Utils backdoor"]
            keywords_threat_actor_tt = ["APT", "nation-state actor", "cyber espionage", "cyber warfare", "organized crime group", "hacktivism", "insider threat", "initial access broker", "reconnaissance", "persistence mechanism", "lateral movement", "defense evasion", "exfiltration", "impact", "MITRE ATT&CK", "TTPs", "IOCs", "IOAs", "threat intelligence report", "threat landscape"]
            keywords_data_infra = ["PII", "PHI", "PCI DSS", "critical infrastructure", "OT security", "ICS security", "SCADA system", "IoT security", "firmware exploit", "hardware backdoor", "network device compromise", "VPN vulnerability", "remote access trojan", "endpoint detection and response", "security information and event management"]

            lower_content = content.lower()
            relevant_keywords_found = [kw for kw in (keywords_basic + keywords_ai_ml + keywords_cloud + keywords_data_infra + keywords_threat_actor_tt + keywords_phishing_social_eng + keywords_ransomware + keywords_supply_chain + keywords_zero_day_exploit) if kw in lower_content]

            if relevant_keywords_found:
                item_data = {
                    'url': url,
                    'title': title,
                    'content': content,
                    'author': author,
                    'timestamp': time.time(),
                    'relevant_keywords_found': relevant_keywords_found
                }
                extracted_items.append(item_data)
                print(f"    [+] RELEVANT POST FOUND - Title: {title[:70]}..., Author: {author} (Keywords: {', '.join(relevant_keywords_found)})")
            else:
                print(f"    [-] Post found but not relevant (no keywords): {title[:70]}...")

        return extracted_items

    except requests.exceptions.ProxyError as e:
        print(f"[-] Proxy Error (Tor connection issue): {e}. Attempting IP renewal...")
        renew_tor_ip()
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection Error (Site unreachable or blocked): {e}. Attempting IP renewal...")
        renew_tor_ip()
        return None
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out for {url}. Attempting IP renewal...")
        renew_tor_ip()
        return None
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        print(f"[-] HTTP Error for {url}: {status_code} - {e.response.reason}.")
        if status_code in [403, 404, 500, 503]:
            print("    Attempting IP renewal due to HTTP error...")
            renew_tor_ip()
        return None
    except Exception as e:
        print(f"[-] An unexpected error occurred while fetching {url}: {e}")
        return None

def run_dark_web_scraper(target_urls, ip_rotation_interval=10):
    all_scraped_data = []
    request_counter = 0

    print("--- Starting Dark Web Threat Intelligence Scraper ---")
    current_ip = get_current_ip()
    print(f"Initial Public IP (via Tor): {current_ip}")

    # Use the target_urls passed from the command line
    for target_url in target_urls:
        print(f"\n--- Processing Target: {target_url} ---")
        
        # This loop is for visiting multiple pages on a single site, or just retrying the same page.
        for page_num in range(1):
            actual_url_to_scrape = target_url

            sleep_time = random.uniform(8, 20)
            print(f"[*] Waiting for {sleep_time:.2f} seconds before next request to {actual_url_to_scrape}...")
            time.sleep(sleep_time)

            data = scrape_onion_url(actual_url_to_scrape)
            if data:
                all_scraped_data.extend(data)
                request_counter += 1

            # Use the ip_rotation_interval passed from the command line
            if request_counter % ip_rotation_interval == 0 and request_counter > 0:
                print(f"[*] Rotating IP after {request_counter} requests...")
                renew_tor_ip()
                new_ip = get_current_ip()
                print(f"New Public IP (via Tor): {new_ip}")

    print("\n--- Scraping Process Complete ---")
    print(f"Total relevant items scraped: {len(all_scraped_data)}")

    if all_scraped_data:
        file_name = f"threat_intel_data_{int(time.time())}.json"
        try:
            with open(file_name, 'w', encoding='utf-8') as f:
                json.dump(all_scraped_data, f, ensure_ascii=False, indent=4)
            print(f"[+] Scraped data saved to '{file_name}'")
            print("    Remember to encrypt this file if it contains sensitive information.")
            
        except Exception as e:
            print(f"[-] Error saving data to file: {e}")

    print("\n--- Final Operational Security & Ethical Reminders ---")
    print("1. ALWAYS ensure Anonsurf is active and your traffic is routed through Tor.")
    print("2. Operate within a dedicated Virtual Machine (Parrot OS is ideal) to contain any risks.")
    print("3. Never download or execute unknown files from the dark web. Be extremely wary of links.")
    print("4. Be prepared for slow responses and site unreachability - the dark web is volatile.")
    print("5. Double-check the legal implications of scraping specific content in your jurisdiction.")
    print("6. Your research is for threat intelligence for your business; focus on patterns and general information, not individual's private data or illegal activities.")


if __name__ == "__main__":
    # --- Command-line argument parsing ---
    parser = argparse.ArgumentParser(description="Dark Web Threat Intelligence Scraper using Tor.")
    parser.add_argument(
        '-u', '--urls',
        nargs='+',  # This tells argparse to accept one or more arguments
        required=True,
        help='List of .onion URLs to scrape. Separate URLs with spaces.'
    )
    parser.add_argument(
        '-i', '--ip_rotate_interval',
        type=int,
        default=10,
        help='Number of requests to make before rotating the Tor IP address. Defaults to 10.'
    )
    
    args = parser.parse_args()

    # Pass the parsed arguments to the main scraper function
    run_dark_web_scraper(target_urls=args.urls, ip_rotation_interval=args.ip_rotate_interval)