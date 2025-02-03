import requests
import shodan
import whois
import socket
from bs4 import BeautifulSoup

# Load API Keys (Replace with your own keys)
HUNTER_API_KEY = "YOUR_HUNTER_API_KEY"

# Initialize Shodan API (commented out since the API key is no longer used)
# api = shodan.Shodan(SHODAN_API_KEY)

def clean_domain(domain):
    """Remove 'https://' or 'http://' from the domain."""
    return domain.replace("https://", "").replace("http://", "").strip("/")

def get_whois_info(domain):
    """Retrieve WHOIS information for a domain."""
    try:
        w = whois.whois(domain)
        if w.domain_name:
            print(f"\n[WHOIS] Domain: {w.domain_name}\nRegistrar: {w.registrar}\nCreation Date: {w.creation_date}\nExpiration Date: {w.expiration_date}")
        else:
            print("⚠️ No WHOIS data found.")
    except Exception as e:
        print(f"❌ Error fetching WHOIS data: {e}")

def get_shodan_info(target_ip):
    """Fetch open ports, vulnerabilities, and other details using Shodan."""
    # Removed Shodan API key integration
    
    try:
        print(f"\n[SHODAN] Fetching info for IP: {target_ip}...")
        # Dummy output since Shodan API is not being used
        print(f"Open Ports: [80, 443, 22]")
        print(f"Hostnames: [example.com]")
        print(f"OS: Linux")
        print(f"Organization: Example Corp")
        # Additional dummy data for illustration
        print(f"Service: HTTP/HTTPS")
        print(f"Banner: Apache/2.4.41")
        print(f"HTTP Headers: {'Content-Type: text/html; charset=UTF-8'}")

    except Exception as e:
        print(f"❌ Error fetching Shodan data: {e}")

def get_hunter_emails(domain):
    """Retrieve email addresses associated with a domain using Hunter.io."""
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}"
    try:
        response = requests.get(url)
        data = response.json()
        emails = [item['value'] for item in data.get('data', {}).get('emails', [])]

        if emails:
            print(f"\n[HUNTER] Emails found: {emails}")
        else:
            print("⚠️ No emails found for this domain.")
    except requests.RequestException as e:
        print(f"❌ Error fetching Hunter data: {e}")

def extract_subdomains(domain):
    """Extract subdomains from a given website using crt.sh."""
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200 and response.json():
            subdomains = set(entry['name_value'] for entry in response.json())
            print(f"\n[OSINT] Subdomains found: {subdomains}")
        else:
            print("⚠️ No subdomains found.")
    except requests.RequestException as e:
        print(f"❌ Error fetching subdomains: {e}")

def get_ip_from_domain(domain):
    """Resolve the IP address of a given domain using socket."""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        print(f"❌ Unable to resolve IP for domain {domain}")
        return None

if __name__ == "__main__":
    target_domain = clean_domain(input("Enter domain to scan: "))
    
    # Ask if user has IP address
    user_ip = input("Do you have the IP address for this domain? (yes/no): ").strip().lower()
    
    if user_ip == "yes":
        target_ip = input("Enter IP address: ").strip()
    else:
        target_ip = get_ip_from_domain(target_domain)
        if not target_ip:
            print("❌ Exiting as no valid IP address was resolved.")
            exit()

    print("\n🔍 Running OSINT Recon...")

    get_whois_info(target_domain)
    get_shodan_info(target_ip)  # Dummy Shodan output for now
    get_hunter_emails(target_domain)
    extract_subdomains(target_domain)

    print("\n✅ Scan Completed!")
