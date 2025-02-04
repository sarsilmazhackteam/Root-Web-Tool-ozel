# Root Security Scanner
Root Security Scanner, web uygulamalarındaki güvenlik açıklarını tespit etmek için geliştirilmiş Python tabanlı bir güvenlik tarayıcıdır. Komut enjeksiyonu, dizin gezintisi, dosya dahil etme, XSS, CSRF, dosya yükleme açıklıkları, WAF tespiti ve bypass teknikleri gibi birçok güvenlik testini otomatik olarak gerçekleştirir.

# Özellikler
✅ Komut Enjeksiyonu testi
✅ Açık Dizin tespiti
✅ Dosya Dahil Etme (LFI) güvenlik açığı tespiti
✅ XSS (Cross-Site Scripting) güvenlik açığı tespiti
✅ CSRF (Cross-Site Request Forgery) güvenlik açığı tespiti
✅ Dosya Yükleme Açıkları ve bypass denemeleri
✅ WAF Tespiti ve Bypass Teknikleri
✅ SQLMap ile Veritabanı Tespiti
✅ Port Taraması

# Kurulum
1. Gerekli Bağımlılıkları Yükleyin
Python 3.x'in yüklü olduğundan emin olun. Ardından, gerekli kütüphaneleri yüklemek için aşağıdaki komutu çalıştırın:

***pip install requests urllib3 termcolor pyfiglet colorama***

SQLMap'in sisteminizde kurulu olması gerekmektedir. Eğer yoksa, şu komutla kurabilirsiniz:

***git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap
cd sqlmap
python sqlmap.py --help***

# Kullanım
1. Tool'u Çalıştırın
Aşağıdaki komutu kullanarak Root Security Scanner'ı başlatabilirsiniz:

***python SARSİLMAZ.py***

2. URL Girin
Tool çalıştırıldığında, analiz etmek istediğiniz URL’yi girin:

***[?] Taranacak URL: https://hedefsite.com***

3. Otomatik Güvenlik Testleri
Tool, girilen URL’ye karşı çeşitli güvenlik testleri gerçekleştirecektir. Eğer bir güvenlik açığı tespit edilirse, kırmızı renkte gösterilecektir.

***[*] Komut Enjeksiyonu testi yapılıyor...
[!] Komut Enjeksiyonu açığı bulundu!***
Test Edilen Güvenlik Açıkları
Açık Türü	Açıklama
Komut Enjeksiyonu	Web uygulamasının komut satırına zararlı komutlar enjekte edilebilir mi?
Açık Dizin Testi	Web sunucusunda açık dizin erişimi var mı?
Dosya Dahil Etme (LFI)	../../etc/passwd gibi yollarla dosya dahil etme açığı var mı?
XSS Açığı	Kullanıcının tarayıcısında zararlı script çalıştırılabilir mi?
CSRF Açığı	Kullanıcı kimliği doğrulama mekanizması zayıf mı?
Dosya Yükleme Açıkları	Zararlı dosyalar yüklenebilir ve çalıştırılabilir mi?
WAF Tespiti	Web Uygulama Güvenlik Duvarı (WAF) var mı?
WAF Bypass Teknikleri	WAF engellerini aşmak için teknikler denenir.
SQLMap ile Veritabanı Tespiti	SQL Injection güvenlik açığı var mı?
Port Taraması	Belirlenen portlar açık mı?
Örnek Çıktılar
1. Komut Enjeksiyonu Açığı Bulunduğunda:

***[*] Komut Enjeksiyonu testi yapılıyor...
[!] Komut Enjeksiyonu açığı bulundu!***

2. Açık Dizin Testi Sonucu:

***[*] Açık dizin testi yapılıyor...
[+] Açık dizin bulunamadı.***

3. Dosya Dahil Etme Açığı Bulunduğunda:

***[*] Dosya Dahil Etme testi yapılıyor...
[!] Dosya Dahil Etme açığı bulundu!***

4. SQLMap Taraması Sonucu:

***[*] SQLMap ile veritabanları tespit ediliyor...***
***[!] Bulunan veritabanları:***
*- admin_db*
*- users_db*

WAF Bypass Denemeleri
Tool, aşağıdaki WAF bypass tekniklerini denemektedir:

✔ Parametre Kirliliği: ?id=1&id=2
✔ Büyük/Küçük Harf Manipülasyonu: ?id=1 AND 1=1
✔ Null Byte Injection: ?id=1%00
✔ Content-Type Manipülasyonu: JSON formatında istek gönderme

Başarıyla WAF bypass edilirse, şu mesaj gösterilir:

***[!] Parametre Kirliliği ile WAF bypass edildi!***
Port Taraması
Varsayılan olarak şu portlar taranır:

***✅ 80 (HTTP)
✅ 443 (HTTPS)
✅ 8080 (Alternatif HTTP Portu)
✅ 21 (FTP)
✅ 22 (SSH)
✅ 3306 (MySQL)***

Açık portlar yeşil renkte, kapalı portlar kırmızı renkte gösterilir:

***[+] Port 80 açık.
[-] Port 3306 kapalı.***

# Yasal Uyarı

*Bu araç, yalnızca yasal testler ve eğitim amaçlı kullanılmalıdır. İzinsiz sızma testleri suçtur ve yasal sorumluluk gerektirir. Kullanımından doğabilecek tüm yasal sorumluluk kullanıcıya aittir.*

**👤 Sarsılmaz Hack Team - Telegram**

***Eğitim İçindir, Kötüye Kullanım Yasaktır!***
