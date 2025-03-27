import requests
import re
import argparse
import json
import socket

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.headers = {"User-Agent": "Mozilla/5.0"}

    def print_banner(self):
        banner = r"""
               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/
 
                                   
        SubFinder - OSINT Tool
        """
        print(banner)

    def search_google(self):
        url = f"https://www.google.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)

    def search_bing(self):
        url = f"https://www.bing.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
    
    def search_yahoo(self):
        url = f"https://www.yahoo.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
    
    def search_dnsdumpster(self):
        url = f"https://www.dnsdumpster.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
        
    def search_ask(self):
        url = f"https://www.ask.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
        
    def search_netcraft(self):
        url = f"https://www.netcraft.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
        
    def search_baidu(self):
        url = f"https://www.baidu.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
        
    def search_threatcrowd(self):
        url = f"https://www.threatcrowd.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
        
    def search_crtsearch(self):
        url = f"https://www.crtsearch.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)
        
    def search_passivedns(self):
        url = f"https://www.passivedns.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)

    def search_virustotal(self):
        url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            data = response.json()
            for sub in data.get("data", []):
                self.subdomains.add(sub["id"])
                
    def extract_subdomains(self, text):
        pattern = rf"([a-zA-Z0-9._-]+\.{re.escape(self.domain)})"
        found = re.findall(pattern, text)
        for sub in found:
            self.subdomains[sub] = None  # Placeholder for IP address

    def resolve_ip_addresses(self):
        print("\n[+] Resolving IP addresses...")
        for sub in self.subdomains.keys():
            try:
                ip = socket.gethostbyname(sub)
                self.subdomains[sub] = ip
            except socket.gaierror:
                self.subdomains[sub] = "Could not resolve"
                
    def save_results(self):
        output_file = "json.txt"
        result = {"domain": self.domain, "subdomains": self.subdomains}
        with open(output_file, "w") as f:
            json.dump(result, f, indent=4)
        print(f"\n[+] Results saved in {output_file}")

    def run(self):
        self.print_banner()
        print(f"\nFinding subdomains for: {self.domain}")
        self.search_google()
        self.search_bing()
        self.search_virustotal()
        self.search_yahoo()
        self.search_dnsdumpster()
        self.search_ask()
        self.search_netcraft()
        self.search_baidu()
        self.search_threatcrowd()
        self.search_crtsearch()
        self.search_passivedns()
        
        self.resolve_ip_addresses()
        
        print("\n[+] Discovered Subdomains with IPs:")
        for sub, ip in self.subdomains.items():
            print(f"{sub} -> {ip}")

        self.save_results()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Subdomain Finder with IP Resolution")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    args = parser.parse_args()

    finder = SubdomainFinder(args.domain)
    finder.run()
