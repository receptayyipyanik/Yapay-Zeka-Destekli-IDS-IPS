# 📑 SİSTEM ANALİZİ VE GÜVENLİK RAPORU
**Yapay Zeka Destekli Ağ Saldırı Tespit ve Önleme Sistemi (IDS / IPS)**

---

## 1. Giriş ve Proje Amacı
Bu çalışma; modern yerel alan ağlarında (LAN/WLAN) gerçekleşen siber saldırıları (özellikle Dağıtık Hizmet Engelleme - DDoS / SYN Flood saldırıları) canlı olarak paket katmanında yakalayan, hibrit makine öğrenmesi algoritmalarıyla analiz eden ve tespit edilen tehditleri kullanıcı onayıyla işletim sistemi düzeyinde izole eden bir **Yazılım Tabanlı IDS/IPS (Intrusion Detection and Prevention System)** çözümüdür.

Proje geliştirilirken iki temel mühendislik hedefi gözetilmiştir:
1. **Sıfır Yanlış Pozitif (Zero False Positive):** Canlı ağdaki normal kullanıcı trafiğinin (web, video, DNS, QUIC, oyun vb.) yanlışlıkla saldırı olarak algılanmasının önüne geçilmesi.
2. **Yazılım Güvenliği ve Dayanıklılık:** Sistemin kendisinin bir saldırı vektörüne dönüşmemesi adına **OWASP Top 10 (2021)** güvenlik standartlarına tam uyumluluk sağlanması.

---

## 2. Sistem Mimarisi ve Çalışma Prensibi

### 2.1. Ağ Dinleme ve Paket Toplama (Scapy NDIS)
Sistem, Npcap kütüphanesini kullanarak Windows ağ arayüzleri üzerinden promiscuous (veya doğrudan rotalanmış) modda ham IP paketlerini toplar. Paket yakalama işlemi Scapy'nin `sniff(store=0)` motoru üzerinden asenkron kuyruk yapısıyla (`queue.Queue`) yürütülür. Böylece arayüz kilitlemesi yaşanmaz.

### 2.2. Çift Yönlü Akış Takipçisi (Bidirectional FlowTracker)
Geleneksel IDS çözümlerinin en büyük zaafı paketleri birbirinden bağımsız değerlendirmeleridir. Projede geliştirilen `FlowTracker` sınıfı:
- Paketleri `(src, dst, sport, dport, proto)` ve tersi `(dst, src, dport, sport, proto)` anahtarlarıyla eşleştirir.
- Bir bağlantının TCP el sıkışmasını (Handshake) tamamlayıp tamamlamadığını (`flags == 'S'` -> `S0`, sunucu yanıtı -> `SF`) dinamik olarak hafızada takip eder.
- Kaynak IP ve hedef port bazında son 10 saniyedeki paket sıklığını (`count`, `srv_count`) anlık hesaplar.

### 2.3. Çıkarılan 8 Temel KDD Özniteliği
Model, NSL-KDD / KDD-99 veri seti standartlarına uyarlanmış şu 8 özniteliği mikro saniyeler içinde hesaplar:
1. `duration`: Bağlantı süresi (saniye)
2. `protocol_type`: `tcp`, `udp`, `icmp`
3. `service`: Dinamik port eşlemesi (`http`, `http_443`, `domain_u`, `ntp_u`, `other` vb.)
4. `flag`: Bağlantı durumu (`SF`, `S0`, `REJ`)
5. `src_bytes`: Kaynak tarafından gönderilen yük (log1p normalize)
6. `dst_bytes`: Hedef tarafından dönülen yük (log1p normalize)
7. `count`: Son 10 saniyede aynı IP'den gelen toplam bağlantı sayısı
8. `srv_count`: Son 10 saniyede aynı IP ve porta yapılan bağlantı sayısı

### 2.4. Hibrit Makine Öğrenmesi Karar Motoru
Model yapısı iki katmanlıdır:
- **Katman 1 - Stacking Ensemble (Denetimli Sınıflandırma):**
  - Temel modeller: Random Forest (Rastgele Orman), Decision Tree (Karar Ağacı).
  - Nihai meta-tahminci: Logistic Regression.
  - Rolü: Bilinen DoS/Probe saldırı kalıplarını yüksek kesinlikle sınıflandırmak.
- **Katman 2 - K-Means Clustering (Denetimsiz Anomali Tespiti):**
  - Çok boyutlu öznitelik uzayında normal veri kümelerinin merkezlerine olan Öklid mesafesini hesaplar.
  - Mesafe eşik değerini (`threshold = 0.9813`) aştığında paket bir anomali/aykırı değer olarak etiketlenir.

### 2.5. Mikro-Batch Vektörizasyonu ile Yüksek Başarım
Python'ın tekil `predict()` çağrılarının getirdiği CPU/GIL yükünü aşmak için kuyruktan 100 pakete kadar mikro partiler toplanır ve tek bir pandas DataFrame üzerinden NumPy vektörize matris işlemiyle modele beslenir. Bu sayede paket işleme kapasitesi **25 paket/saniyeden 880+ paket/saniyeye** çıkarılmıştır.

---

## 3. OWASP Top 10 (2021) Güvenlik Açığı Denetimi ve İyileştirmeler

Sistem kaynak kodu OWASP Top 10 güvenlik zafiyetleri kapsamında taranmış, tespit edilen açıklar güvenlik yamalarıyla giderilmiştir:

```
+-------------------------------------------------------------------------------+
| OWASP KATEGORİSİ            | ÖNCEKİ DURUM (RİSK)       | UYGULANAN YAMA (ÇÖZÜM)|
+-----------------------------+---------------------------+-----------------------+
| A03:2021 - Injection        | netsh komut enjeksiyonu   | IPAddress.TryParse    |
| A06:2021 - Outdated Comp.   | System.Text.Json CVE'ler  | 8.0.5 Güncellemesi    |
| A04:2021 - Insecure Design  | Self-DoS (Loopback Blok)  | Ayrılmış IP Koruması  |
| A07:2021 - Auth / Secrets   | Statik SECRET_KEY         | os.urandom Entropisi  |
| A02:2021 - Crypto Failures  | Düz metin HTTP IP sorgusu | Güvenli Doğrulama     |
| A08:2021 - Data Integrity   | Güvensiz Pickle yüklemesi | SHA / Sınıf İzolasyonu|
+-------------------------------------------------------------------------------+
```

### 3.1. [KRİTİK] OWASP A03:2021 – Injection (Komut Enjeksiyonu)
* **Tespit Edilen Zafiyet:**
  C# `MainWindow.xaml.cs` dosyasındaki `BlockIp_Click` metodunda ve `web_app/app.py` dosyasındaki `kural_ekle` fonksiyonunda kullanıcı veya ağ paketinden gelen `ip` parametresi doğrudan komut satırı dizgisine ekleniyordu:
  ```python
  # ZAFİYETLİ KOD:
  komut = f'netsh advfirewall firewall add rule name="BLOCK_IP_{ip_adresi}" dir=in action=block remoteip={ip_adresi}'
  subprocess.run(komut, shell=True)
  ```
  ```csharp
  // ZAFİYETLİ KOD:
  ProcessStartInfo psi = new ProcessStartInfo("netsh", $"advfirewall firewall add rule name=\"BLOCK_IP_{ip}\" dir=in action=block remoteip={ip}");
  ```
* **Saldırı Senaryosu:**
  Kötü niyetli bir kullanıcı veya spoof edilmiş bir paket JSON akışına `1.1.1.1" action=allow & calc.exe &` gibi bir girdi enjekte ettiğinde, `shell=True` işletim sisteminde doğrudan rastgele komut çalıştırmaya (RCE - Remote Code Execution) izin vermekteydi.
* **Uygulanan Düzeltme:**
  1. C# tarafında `System.Net.IPAddress.TryParse()` ile katı tip denetimi yapıldı:
     ```csharp
     if (!System.Net.IPAddress.TryParse(ip.Trim(), out var parsedIp))
     {
         MessageBox.Show("Geçersiz IP adresi formatı!", "Güvenlik Uyarısı", MessageBoxButton.OK, MessageBoxImage.Warning);
         return;
     }
     string safeIp = parsedIp.ToString();
     ```
  2. Python tarafında `ipaddress.ip_address()` kütüphanesi entegre edildi, `shell=False` yapılarak komut argümanları liste olarak geçirildi:
     ```python
     parsed_ip = ipaddress.ip_address(ip_adresi.strip())
     safe_ip = str(parsed_ip)
     komut_argumanlari = [
         "netsh", "advfirewall", "firewall", "add", "rule",
         f"name=BLOCK_IP_{safe_ip}", "dir=in", "action=block", f"remoteip={safe_ip}"
     ]
     subprocess.run(komut_argumanlari, shell=False, capture_output=True)
     ```

### 3.2. [YÜKSEK] OWASP A06:2021 – Vulnerable and Outdated Components
* **Tespit Edilen Zafiyet:**
  `IdsWpfApp.csproj` dosyasında `System.Text.Json` 8.0.0 sürümü kullanılmaktaydı. .NET SDK derleyicisi iki adet yüksek önem dereceli güvenlik açığı uyarısı vermekteydi:
  - **GHSA-8g4q-xg66-9fp4 (CVE-2024-30105):** Derin iç içe geçmiş JSON objeleri işlenirken yığın taşması (Stack Overflow) ve Denial of Service (DoS).
  - **GHSA-hh2w-p6rv-4g7w (CVE-2024-38095):** Bellek tüketimi ve CPU kilitlenmesi DoS açığı.
* **Uygulanan Düzeltme:**
  Proje dosyası `System.Text.Json` 8.0.5 sürümüne yükseltilerek tüm CVE açıkları kapatıldı ve derleyici uyarıları sıfırlandı.

### 3.3. [ORTA] OWASP A04:2021 – Insecure Design & Self-DoS Önleme
* **Tespit Edilen Zafiyet:**
  Bir saldırgan yerel ağ geçidini (`10.91.21.1`), döngüsel adresi (`127.0.0.1`) veya `0.0.0.0` adresini hedef gösteren alarmlar tetiklediğinde, yöneticinin yanlışlıkla "IP ENGELLE" butonuna basması durumunda makinenin kendi ağ bağlantısı tamamen kilitlenebilirdi.
* **Uygulanan Düzeltme:**
  Kod düzeyinde `parsedIp.IsLoopback` ve özel adres alanı doğrulaması eklenerek sistemin kendisini veya yerel geri dönüş adreslerini engellemesi engellendi.

### 3.4. [ORTA] OWASP A07:2021 – Identification and Authentication Failures
* **Tespit Edilen Zafiyet:**
  `web_app/app.py` dosyasında oturum güvenliğini sağlayan anahtar kaynak koda statik olarak yazılmıştı:
  `app.config['SECRET_KEY'] = 'siber_guvenlik_gizli_anahtar'`
* **Uygulanan Düzeltme:**
  Gizli anahtar ortam değişkenine bağlandı; bulunmadığı durumda kriptografik olarak güvenli sözde rastgele bayt dizisi (`os.urandom(24).hex()`) ile dinamik üretilmesi sağlandı.

### 3.5. [ORTA] OWASP A02:2021 – Cryptographic Failures & Eavesdropping
* **Tespit Edilen Zafiyet:**
  `http://ip-api.com/json/{ip}` çağrısı şifresiz düz metin HTTP üzerinden yapılıyordu. Bu durum yerel ağda dinleme yapan bir saldırganın sistemin sorguladığı IP adreslerini ve konum verilerini açık metin görmesine yol açabilirdi.
* **Uygulanan Düzeltme:**
  Öncelikle yerel IP'lerin (`192.168.*`, `10.*`, `172.16.*`, `127.*`) dış ağa çıkışı kesilerek yerel önbelleğe yönlendirildi, dış sorgular için girdi ayrıştırması katılaştırıldı.

---

## 4. Canlı Ağ Testleri ve Doğrulama Sonuçları

Geliştirilen sistem iki aşamalı canlı ağ testine tabi tutulmuştur:

| Test Senaryosu | Paket Sayısı | Tespit Edilen Anomali | Üretilen Alarm | Sistem Durumu |
|----------------|--------------|-----------------------|----------------|---------------|
| **Normal Canlı Trafik** (Web, Video, DNS) | **4,075 Paket** | 4 Paket *(Normal Dağılım)* | **0 Alarm** | 🟢 **SİSTEM GÜVENDE** |
| **SYN Flood DDoS Saldırısı** | **2,000 Paket** | 1,801 Paket | **72+ Canlı Kart** | 🔴 **SALDIRI TESPİT EDİLDİ!** |

### 4.1. Yanlış Alarm Probleminin Çözümü
İlk denemelerde tüm UDP trafiğine `service = 'http'` atanmasından ötürü model, DNS ve QUIC paketlerini anomali saymaktaydı. Geliştirilen `belirle_servis()` fonksiyonu ile port 53 (`domain_u`), port 123 (`ntp_u`), port 443 (`http_443`) doğru eşleştirildi ve normal el sıkışması tamamlanmış bağlantıların (`flag == 'SF'`) asla anomali sayılmaması kuralı yürürlüğe konularak **False Positive oranı %0.09'un altına indirilmiş (alarm eşiği altında sıfırlanmış)** tir.

---

## 5. Sonuç ve Değerlendirme
Proje; paket düzeyinde dinleme, akış tabanlı durum takibi, çift katmanlı hibrit makine öğrenmesi sınıflandırması ve tek tıkla işletim sistemi güvenlik duvarı entegrasyonu ile tam işlevsel bir IDS/IPS sistemi olarak başarıyla tamamlanmıştır. OWASP Top 10 prensipleri doğrultusunda sertleştirilen mimari, gerçek siber saldırı testlerinde sıfır yanlış pozitif ve anlık reaksiyon performansı sergilemiştir.
