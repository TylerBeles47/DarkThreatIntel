# Dark Web Threat Intelligence Scraper
This project provides a set of secure and robust tools for conducting threat intelligence research on the dark web. By leveraging the Tor network, the scripts anonymize traffic and automate the process of fetching and analyzing content from .onion sites, specifically targeting cybersecurity threats, vulnerabilities, and malicious activities.

The project includes two primary scraping scripts, each designed for a different level of complexity and site type:

- **dark.py**: A lightweight, fast scraper for static HTML sites.
- **dark2.py**: A powerful, browser-based scraper for dynamic, JavaScript-heavy sites.

**Disclaimer**: This tool is intended for legal and ethical cybersecurity research purposes only. The user assumes all responsibility for adhering to local laws and regulations. Using this tool for any illegal activities is strictly prohibited. Always operate within a secure, isolated environment, such as a dedicated Virtual Machine (e.g., Parrot OS), to contain any potential risks.

## Key Features
- **Dual Scraping Methods**: Choose between a fast, requests-based scraper for static content and a more robust, tbselenium-based scraper for dynamic websites.

- **Tor Network Integration**: All web traffic is routed through the Tor network, ensuring anonymity and security for both scripts.

- **Dynamic IP Rotation**: The requests script can automatically rotate the Tor IP address to prevent blocking. The tbselenium script maintains a persistent session, which is often more effective for sites with waiting rooms or complex anti-bot measures.

- **Comprehensive Keyword Analysis**: Both scripts are pre-configured with an extensive list of keywords across various threat categories, including:

  - General Cyber Threats: Malware, DDoS, data breaches.
  - AI/ML-Specific Threats: WormGPT, FraudGPT, model poisoning.
  - Cloud Security Threats: AWS, Azure, Kubernetes exploits.
  - Specific Attack Types: Ransomware, zero-day exploits, supply chain attacks.

- **Robust Error Handling**: The scripts are built to handle connection errors, timeouts, and HTTP errors gracefully.

- **Structured Output**: Scraped data is saved as a clean, structured JSON file for easy analysis and integration into other tools.

## Prerequisites

- **Python 3.x**
- **Tor**: The Tor daemon must be running in the background. A tool like Anonsurf is highly recommended for securely routing all system traffic through Tor.
- **Tor Control Port**: The Tor control port must be enabled. You may need to edit your torrc file (typically `/etc/tor/torrc`) to uncomment `ControlPort 9051` and `CookieAuthentication 1` or `HashedControlPassword`.
- **Tor Browser** (for dark2.py): You must have the Tor Browser Bundle installed. You will need to update the `TBB_PATH` variable in the dark2.py file to its absolute path.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/tbeles/DarkThreatIntel.git
cd DarkThreatIntel
```
2. Install Python dependencies:

   For dark.py (requests scraper):
   ```bash
   pip install requests beautifulsoup4 stem
   ```

   For dark2.py (tbselenium scraper):
   ```bash
   pip install beautifulsoup4 tbselenium selenium
   ```

   You can install all dependencies at once if you plan to use both:
   ```bash
   pip install requests beautifulsoup4 stem tbselenium selenium
   ```
3. Configure Tor Browser Path (for dark2.py only):

   Open dark2.py and update the `TBB_PATH` variable to the absolute path of your Tor Browser installation. The default is set for a typical Parrot OS installation.

   ```python
   # IMPORTANT: Set this to the exact root path of your Tor Browser bundle.
   TBB_PATH = os.path.expanduser('~/.local/share/torbrowser/tbb/x86_64/tor-browser')
   ```
## Usage

Both scripts are executed from the command line and require one or more .onion URLs.

### Using dark.py

This script is ideal for sites with minimal JavaScript. It is faster and uses fewer resources.

```bash
python dark.py -u http://forum1.onion http://blog2.onion
```

**Options:**
- `-u, --urls`: A space-separated list of .onion URLs to scrape. (Required)
- `-i, --ip_rotate_interval`: Number of requests before rotating the Tor IP. Defaults to 10.

### Using dark2.py

This script is for modern, JavaScript-heavy sites. It is more robust but also slower and more resource-intensive.

```bash
python dark2.py -u http://dynamic-site.onion http://another-site.onion
```

**Options:**
- `-u, --urls`: A space-separated list of .onion URLs to scrape. (Required)
- `-H, --headless`: Run the browser in headless mode (no GUI window).

## Important Operational Security & Ethical Reminders

- **Isolation is Key**: Always run these scripts within a Virtual Machine. This prevents any potential malware or exploits from affecting your host system.

- **Anonsurf**: Confirm that Anonsurf is active (`anonsurf status`) before starting the scripts. This provides a crucial layer of security by routing all traffic through Tor.

- **No File Downloads**: The scripts are designed for text-based analysis. Never download or execute any files from the dark web.

- **Site-Specific Logic**: The HTML parsing logic is tailored to a specific website structure. If you target a new site, you will need to inspect its HTML and adjust the extraction code in the `scrape_onion_url` (for requests) or `scrape_onion_with_tbselenium` (for tbselenium) functions accordingly.

- **Expect Volatility**: Dark web sites are often slow, unstable, and may go offline without warning. The scripts' error handling helps, but be prepared for high failure rates on certain sites.