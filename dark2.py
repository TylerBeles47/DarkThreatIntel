import os
import time
import random
import re
import json
from bs4 import BeautifulSoup
import argparse

# tbselenium imports
try:
    from tbselenium.tbdriver import TorBrowserDriver
    import tbselenium.common as cm
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver import DesiredCapabilities
    TBS_AVAILABLE = True
except ImportError:
    print("[ERROR] tbselenium is not installed. This script requires it.")
    print("        Please install: pip install selenium tbselenium")
    TBS_AVAILABLE = False


# --- Configuration ---
# IMPORTANT: Set this to the exact root path of your Tor Browser bundle.
# Based on common installations on Parrot OS:
TBB_PATH = os.path.expanduser('~/.local/share/torbrowser/tbb/x86_64/tor-browser')

# Tor Control Port (Anonsurf often uses 9051)
TOR_CONTROL_PORT = 9051
TOR_SOCKS_PORT = 9050

# --- Keywords for Threat Intelligence (your comprehensive list) ---
KEYWORDS = [
    "malware", "ransomware", "phishing", "spoofing", "botnet", "DDoS",
    "exploit", "vulnerability", "brute force", "keylogger", "spyware",
    "trojan", "worm", "backdoor", "data breach", "data exfiltration",
    "credential theft", "social engineering", "unauthorized access",
    "network intrusion", "firewall bypass", "encryption bypass",
    "packet sniffing", "rootkit", "shellcode", "payload",
    "command and control", "dark web", "deep web", "underground forum",
    "black hat", "threat actor", "wormgpt", "fraudgpt", "evilgpt",
    "ai malware", "ai phishing", "llm exploit", "generative ai cyber",
    "ai-driven attack", "adversarial AI", "model poisoning", "data poisoning",
    "model evasion", "deepfake", "synthetic data attack",
    "AI-powered social engineering", "AI-generated content",
    "AI model theft", "AI bias injection", "machine learning exploit",
    "AI security risk", "AI vulnerability", "AI-enhanced malware",
    "LLM security", "AI red teaming", "aws s3", "azure ad",
    "kubernetes exploit", "cloud misconfiguration", "iam bypass",
    "gcp exploit", "cloud breach", "serverless hack",
    "cloud security posture", "container escape", "docker exploit",
    "kubernetes vulnerability", "cloud native attack", "API security flaw",
    "serverless vulnerability", "SaaS compromise", "IaaS breach",
    "PaaS vulnerability", "cloud identity compromise",
    "storage bucket expose", "cloud access key leak",
    "cloud privilege escalation", "shadow IT cloud",
    "cloud data exfiltration", "multi-cloud security",
    "cloud network segmentation", "ransomware attack", "data encryption",
    "double extortion", "ransom note", "decryption key",
    "Ransomware-as-a-Service", "Ryuk", "Maze", "REvil", "DarkSide",
    "WannaCry", "NotPetya", "Conti", "LockBit", "Clop", "Hive",
    "spear phishing", "whaling", "smishing", "vishing",
    "business email compromise", "email compromise",
    "credential harvesting", "typosquatting", "domain spoofing",
    "look-alike domain", "malicious link", "malicious attachment",
    "pretexting", "baiting", "quid pro quo", "zero-day vulnerability",
    "zero-day exploit", "unpatched vulnerability", "n-day exploit",
    "vulnerability disclosure", "proof-of-concept",
    "remote code execution", "privilege escalation",
    "memory corruption", "buffer overflow", "SQL injection",
    "cross-site scripting", "deserialization vulnerability",
    "log4j exploit", "supply chain compromise",
    "software supply chain attack", "third-party risk",
    "dependency confusion", "software integrity", "code tampering",
    "package manager exploit", "SolarWinds", "3CX attack",
    "XZ Utils backdoor", "APT", "nation-state actor", "cyber espionage",
    "cyber warfare", "organized crime group", "hacktivism",
    "insider threat", "initial access broker", "reconnaissance",
    "persistence mechanism", "lateral movement", "defense evasion",
    "exfiltration", "impact", "MITRE ATT&CK", "TTPs", "IOCs", "IOAs",
    "threat intelligence report", "threat landscape", "PII", "PHI",
    "PCI DSS", "critical infrastructure", "OT security", "ICS security",
    "SCADA system", "IoT security", "firmware exploit",
    "hardware backdoor", "network device compromise", "VPN vulnerability",
    "remote access trojan", "endpoint detection and response",
    "security information and event management"
]

# --- Core Scraping Function using tbselenium ---

def scrape_onion_with_tbselenium(target_urls, is_headless=False):
    """
    Launches Tor Browser, waits for waiting rooms, and then scrapes content
    from a list of URLs within the same browser session.
    """
    if not TBS_AVAILABLE:
        print("[!] tbselenium is not available. Cannot run browser-based scraping.")
        return []

    if not target_urls:
        print("[!] TARGET_ONION_URLS list is empty. No URLs to scrape.")
        return []

    all_scraped_data = []
    driver = None
    try:
        print(f"[*] Launching Tor Browser from: {TBB_PATH}")
        if is_headless:
            print("    Running in headless mode (no GUI window).")

        # Configure capabilities for headless mode
        capabilities = DesiredCapabilities.FIREFOX
        if is_headless:
            print("[INFO] tbselenium headless mode is experimental and may require pyvirtualdisplay.")
            
        driver = TorBrowserDriver(TBB_PATH, tor_cfg=cm.USE_RUNNING_TOR,
                                  socks_port=TOR_SOCKS_PORT, control_port=TOR_CONTROL_PORT,
                                  headless=is_headless)

        for url_to_scrape in target_urls:
            print(f"\n[*] Navigating to: {url_to_scrape}")
            driver.get(url_to_scrape)
            
            try:
                print("    [*] Checking for waiting room...")
                WebDriverWait(driver, 185).until_not(
                    EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Your estimated wait time is')]"))
                )
                print("    [+] Waiting room cleared. Proceeding.")
            except TimeoutException:
                print("    [-] ERROR: Waiting room text did not disappear after 185 seconds. It may be stuck or the site is unresponsive.")
                pass
            
            sleep_time = random.uniform(5, 10)
            print(f"    [*] Waiting for {sleep_time:.2f} seconds for final content load...")
            time.sleep(sleep_time)

            page_source = driver.page_source
            soup = BeautifulSoup(page_source, 'html.parser')

            extracted_items_from_page = []
            posts = soup.find_all('div', class_='forum-post-container')

            if not posts:
                print("    [!] No specific forum posts found. Attempting general text extraction.")
                paragraphs = soup.find_all('p')
                for p in paragraphs: 
                    text = p.get_text(strip=True)
                    if text and not "Your estimated wait time is" in text:
                        extracted_items_from_page.append({'url': url_to_scrape, 'type': 'general_paragraph', 'content': text[:500] + ('...' if len(text) > 500 else '')})
            
            for post in posts:
                title_tag = post.find('h3', class_='post-title')
                content_tag = post.find('div', class_='post-body')
                author_tag = post.find('span', class_='post-author')

                title = title_tag.get_text(strip=True) if title_tag else "N/A"
                content = content_tag.get_text(strip=True) if content_tag else "N/A"
                author = author_tag.get_text(strip=True) if author_tag else "N/A"

                content = re.sub(r'\s+', ' ', content).strip()
                lower_content = content.lower()
                relevant_keywords_found = [kw for kw in KEYWORDS if kw in lower_content]

                if relevant_keywords_found:
                    item_data = {
                        'url': url_to_scrape,
                        'title': title,
                        'content': content,
                        'author': author,
                        'timestamp': time.time(),
                        'relevant_keywords_found': relevant_keywords_found
                    }
                    extracted_items_from_page.append(item_data)
                    print(f"    [+] RELEVANT POST FOUND - Title: {title[:70]}..., Author: {author} (Keywords: {', '.join(relevant_keywords_found)})")

            all_scraped_data.extend(extracted_items_from_page)

    except WebDriverException as e:
        print(f"[-] WebDriver Error: {e}")
        print("    Common WebDriver issues:")
        print("    - Tor Browser path might be incorrect.")
        print("    - Tor is not running or accessible (check Anonsurf status).")
    except Exception as e:
        print(f"[-] An unexpected error occurred during scraping: {e}")
    finally:
        if driver:
            print("\n[*] Closing Tor Browser session.")
            driver.quit()
    
    return all_scraped_data

# --- Main Scraper Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dark Web Threat Intelligence Scraper using tbselenium.")
    parser.add_argument(
        '-u', '--urls',
        nargs='+',
        required=True, # This is the crucial change
        help='List of .onion URLs to scrape. Separated by spaces.'
    )
    parser.add_argument(
        '-H', '--headless',
        action='store_true',
        help='Run the browser in headless mode (no GUI window).'
    )
    
    args = parser.parse_args()

    if not TBS_AVAILABLE:
        print("Script cannot run without tbselenium. Please install it.")
    else:
        if not os.path.exists(TBB_PATH):
            print(f"[CRITICAL ERROR] Tor Browser path not found: {TBB_PATH}")
            print("Please correct the TBB_PATH variable in the script.")
        else:
            # We no longer need to check if args.urls is empty, because required=True handles it.
            scraped_data = scrape_onion_with_tbselenium(args.urls, is_headless=args.headless)

            print("\n--- Scraping Process Complete ---")
            print(f"Total relevant items scraped: {len(scraped_data)}")

            if scraped_data:
                file_name = f"threat_intel_data_{int(time.time())}.json"
                try:
                    with open(file_name, 'w', encoding='utf-8') as f:
                        json.dump(scraped_data, f, ensure_ascii=False, indent=4)
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