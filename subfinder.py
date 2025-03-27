import requests
import re
import sys
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

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()

def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()

def write_file(filename, subdomains):
    # saving subdomains results to output file
    print("%s[-] Saving results to file: %s%s%s%s" % (Y, W, R, filename, W))
    with open(str(filename), 'wt') as f:
        for subdomain in subdomains:
            f.write(subdomain + os.linesep)
            
def subdomain_sorting_key(hostname):
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0

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
        
    def __init__(self, domain):
        if not domain:
            raise ValueError("Domain must be provided!")
        self.domain = domain
        self.engine_name = "SomeEngine"
        self.print_banner()

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
    parser.add_argument("domain", help="Domain to find subdomains for")
    args = parser.parse_args()
    
    print(f"Parsed domain: {args.domain}")  # Debugging print
    finder = SubdomainFinder(args.domain)
    finder.run()
