# 📘 KULLANIM KILAVUZU
**Yapay Zeka Destekli Ağ Saldırı Tespit ve Önleme Sistemi (IDS / IPS)**

Bu kılavuz, projenin bilgisayarınıza kurulumunu, çalıştırılmasını, canlı saldırı testinin gerçekleştirilmesini ve güvenlik duvarı engelleme özelliklerinin kullanımını adım adım açıklamaktadır.

---

## 📌 1. Sistem Gereksinimleri ve Ön Koşullar

Sistemin eksiksiz çalışabilmesi için aşağıdaki yazılımların bilgisayarınızda yüklü olması gerekmektedir:

1. **İşletim Sistemi:** Windows 10 veya Windows 11 (64-bit).
2. **Python:** Python 3.10 veya daha güncel bir sürüm (Kurulum sırasında *"Add Python to PATH"* seçeneği işaretlenmelidir).
3. **.NET SDK:** [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) veya üzeri.
4. **Visual Studio:** Visual Studio 2022 (*.NET Masaüstü Geliştirme* iş yükü ile).
5. **Npcap Sürücüsü (Kritik):**
   - Scapy'nin ağ kartını paket düzeyinde dinleyebilmesi için [Npcap Resmi Sitesi](https://npcap.com/#download) üzerinden Npcap indirilmeli ve kurulmalıdır.
   - ⚠️ **ÖNEMLİ:** Kurulum esnasında gelen seçeneklerde **"Install Npcap in WinPcap API-compatible Mode"** kutucuğu MUTLAKA işaretlenmelidir.

---

## 🚀 2. Kurulum Adımları

### Adım 2.1: Proje Bağımlılıklarının Yüklenmesi
Komut istemini (CMD) veya PowerShell'i proje ana dizininde açın ve aşağıdaki komutu çalıştırın:

```bash
pip install -r requirements.txt
```

Bu komut; `scapy`, `pandas`, `numpy`, `scikit-learn`, `joblib`, `requests`, `flask`, `flask-socketio` ve `pyinstaller` kütüphanelerini yükleyecektir.

### Adım 2.2: .NET Bağımlılıklarının Doğrulanması
Proje klasöründeyken C# bağımlılıklarını geri yüklemek için:

```bash
dotnet restore IdsWpfApp\IdsWpfApp.csproj
```

---

## 🖥️ 3. Uygulamanın Başlatılması

### Yöntem A: Visual Studio 2022 ile (Tavsiye Edilen)
1. `IdsWpfApp\IdsWpfApp.csproj` dosyasını Visual Studio 2022 ile açın.
2. Üst menüden derleme modunun **Debug** veya **Release** olduğunu kontrol edin.
3. **F5** tuşuna basarak (veya yeşil "Başlat" butonuna tıklayarak) uygulamayı çalıştırın.
4. *İpucu:* Güvenlik duvarı engelleme butonlarının UAC (Kullanıcı Hesabı Denetimi) engeline takılmaması için Visual Studio'yu **"Yönetici Olarak Çalıştır"** seçeneğiyle açmanız önerilir.

### Yöntem B: Komut Satırından Çalıştırma
Yönetici yetkileriyle açılmış bir PowerShell penceresinde:

```powershell
dotnet run --project IdsWpfApp
```

---

## 🎯 4. Arayüzün Kullanımı

Uygulama açıldığında modern, koyu temalı bir arayüz ile karşılaşacaksınız:

```
+-----------------------------------------------------------------------------------------+
| SİBER GÜVENLİK MERKEZİ - Python AI Motoru Başlatıldı, Dinleniyor...                     |
+-----------------------------------------------------------------------------------------+
|                                           |                                             |
| [ TRAFİK ÖZETİ ]                          | [ CANLI ALARMLAR VE SALDIRGAN IP'LER ]      |
| Toplam Paket: 1450                        |                                             |
| Anormal Paket: 0                          | Henüz bir tehdit algılanmadı.               |
|                                           |                                             |
| [ SİSTEM DURUMU ]                         |                                             |
| Güncel Tehdit Durumu:                     |                                             |
| 🟢 Sistem Güvende                         |                                             |
+-----------------------------------------------------------------------------------------+
```

1. **Üst Durum Çubuğu:** Python yapay zeka motorunun arka planda başarıyla bağlanıp dinlemeye geçtiğini gösterir (`Python AI Motoru Başlatıldı, Dinleniyor...`).
2. **Trafik Özeti:**
   - **Toplam Paket:** Canlı ağınızdan geçen toplam paket sayısıdır (her saniye güncellenir).
   - **Anormal Paket:** Model tarafından şüpheli/anomali olarak sınıflandırılan paket sayısıdır. Normal gezinmede bu sayaç sıfırda kalır.
3. **Sistem Durumu:** Normal şartlarda yeşil renkte **"Sistem Güvende"** yazar.
4. **Saldırgan Kartları ve IP Engelleme:**
   - Bir saldırı algılandığında saldırgan IP adresi, gönderdiği ardışık paket sayısı, coğrafi lokasyonu ve saldırı zamanı kırmızı bir kart olarak listeye eklenir.
   - Kartın sağında bulunan **"IP ENGELLE"** butonuna tıklandığında, sistem Windows Defender Güvenlik Duvarı'na otomatik olarak kural ekler ve saldırganın bağlantısını anında keser. Buton gri renkte **"ENGELLENDİ"** durumuna geçer.

---

## 💥 5. Gerçek Saldırı Simülasyonunun Gerçekleştirilmesi

Sistemin tespit ve alarm mekanizmasını test etmek için projede özel olarak hazırlanmış Scapy tabanlı bir DDoS/SYN Flood saldırı aracı bulunmaktadır.

1. IDS/IPS masaüstü uygulamanızın açık ve çalışır durumda olduğundan emin olun.
2. Proje ana dizininde bulunan **`GERCEK_SALDIRIYI_BASLAT.bat`** dosyasına çift tıklayın.
   *(Alternatif olarak komut satırından `python GERCEK_SALDIRI.py` çalıştırabilirsiniz).*
3. Konsol ekranında 3 saniyelik geri sayımın ardından 2000 adet gerçek TCP SYN paketi fırlatılmaya başlayacaktır.
4. **Gözlem:**
   - C# arayüzündeki **Anormal Paket** sayacının hızla yükseldiğini,
   - Sistem durumunun anında kırmızı renkte **"SALDIRI TESPİT EDİLDİ!"** olarak değiştiğini,
   - Saldırgan kartının (örneğin yerel Wi-Fi IP'nizin) sağ tarafta canlı olarak listelendiğini göreceksiniz.
5. Saldırı tamamlandığında alarmlar kesilir ve sistem stabil durumuna geri döner.

---

## 🌐 6. Alternatif Web Dashboard'un Kullanımı

Projeye ek olarak Flask ve WebSocket (Socket.IO) tabanlı hafif bir web paneli de dahildir:

1. Komut satırında web uygulamasını başlatın:
   ```bash
   python web_app/app.py
   ```
2. Tarayıcınızdan `http://localhost:5000` adresine gidin.
3. Canlı ağ akışını ve uyarıları web tarayıcınız üzerinden gerçek zamanlı olarak izleyebilirsiniz.

---

## ❓ 7. Sık Karşılaşılan Sorunlar ve Çözümleri

| Sorun | Olası Neden | Çözüm |
|-------|-------------|-------|
| **"Python Hatası: wpcap.dll required via ctypes not found"** | Npcap yüklü değil veya WinPcap uyumluluk modu seçilmemiş. | Npcap'i yeniden kurun ve kurulum penceresindeki *"Install Npcap in WinPcap API-compatible Mode"* kutucuğunu işaretleyin. |
| **"Güvenlik duvarı kuralı eklenirken yetki hatası oluştu"** | Windows Güvenlik Duvarı kuralı eklemek için Yönetici izni gerekiyor. | Visual Studio'yu veya komut satırını sağ tıklayıp **"Yönetici Olarak Çalıştır"** (Run as Administrator) diyerek açın. |
| **"Python bulunamadı" uyarısı** | Python sistem PATH ortam değişkenine eklenmemiş. | Python kurulum programını açıp *"Modify -> Add Python to PATH"* seçeneğini işaretleyin veya `MainWindow.xaml.cs` içerisindeki `FindPythonPath` metoduna Python dizininizi ekleyin. |
| **Paket sayacı artmıyor (0 kalıyor)** | Scapy varsayılan ağ kartını yanlış algılamış olabilir. | İnternete bağlı olduğunuz aktif Wi-Fi veya Ethernet kartınızın açık ve IP almış olduğundan emin olun. |
