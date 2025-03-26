import requests
import re
import argparse
import json

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
        #Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed, no coloring will be used [Check the readme]")
        G = Y = B = R = W = G = Y = B = R = W = ''

else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    
def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''
    
def banner():
    print("""%s
                 ____        _     _ _ _                 _          
                / ___| _   _| |__ | |_ _|(_) _ __ _   _| | _ .__   _ __ 
                \___ \| | | | '_ \| |_ _|| ||  __  |/ _  ||   _-_)|  __|
                 ___) | |_| | |_) | |    | || |  | | (_| ||  (__ | |
                |____/ \__,_|_.__/|_|    |_||_|  |_|\__._|\_ .__||_|%s%s

    """ % (R, W, Y))

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.headers = {
            "User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language': 'en-US,en;q=0.8",
            "Accept-Encoding': 'gzip",
            }
        self.print_banner()
    
    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        """ subclass can override this if they want a fancy banner :)"""
        self.print_(G + "[-] Searching now in %s.." % (self.engine_name) + W)
        return
        
    def search_google(self):
        url = f"https://www.google.com/search?q=site:{self.domain}"
        response = requests.get(url, headers=self.headers)
        self.extract_subdomains(response.text)

    def search_bing(self):
        url = f"https://www.bing.com/search?q=site:{self.domain}"
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
        self.subdomains.update(found)

    def save_results(self):
        output_file = "json.txt"
        result = {"domain": self.domain, "subdomains": list(self.subdomains)}
        with open(output_file, "w") as f:
            json.dump(result, f, indent=4)
        print(f"\n[+] Results saved in {output_file}")

    def run(self):
        print(f"Finding subdomains for: {self.domain}")
        self.search_google()
        self.search_bing()
        self.search_virustotal()
        print("\n[+] Discovered Subdomains:")
        for sub in sorted(self.subdomains):
            print(sub)
        self.save_results()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Subdomain Finder (Inspired by Sublist3r)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    args = parser.parse_args()

    finder = SubdomainFinder(args.domain)
    finder.run()
