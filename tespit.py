# #3.4.6.kısım
import pandas as pd  # Veri analizi ve tablo işlemleri için pandas kütüphanesi
import numpy as np  # Matematiksel işlemler ve dizi yönetimi için numpy kütüphanesi
import joblib  # Kaydedilmiş modelleri (.pkl) yüklemek için kullanılır
import sys  # Sistem düzeyinde işlemler ve çıkış (exit) kontrolü için
from scapy.all import sniff, IP, TCP, ICMP, conf  # Ağ paketlerini yakalamak ve katmanlarını okumak için
from scapy.arch.windows import get_windows_if_list  # Windows üzerindeki ağ arayüzlerini listelemek için
from datetime import datetime  # Zaman damgası oluşturmak için
from sklearn.preprocessing import MinMaxScaler, LabelEncoder  # Veri ölçeklendirme ve kodlama araçları
import warnings  # Uyarı mesajlarını yönetmek için

# Gereksiz performans ve genel uyarıları kullanıcıya göstermemek için kapat
warnings.simplefilter(action='ignore', category=pd.errors.PerformanceWarning)
warnings.filterwarnings("ignore")

# --- KRİTİK: SINIF TANIMI (Yeni eğitimdeki yapıya uygun hale getirildi) ---
class VeriOnIsleyici:  # Canlı veriyi modelin formatına dönüştüren ana sınıf
    def __init__(self):
        self.scaler = MinMaxScaler()  # Sayısal verileri 0-1 arasına sıkıştıran nesne
        self.cat_cols = ['protocol_type', 'service', 'flag']  # Kategorik (metin) sütunların listesi
        self.encoders = {}  # Her kategorik sütun için kullanılacak olan encoder sözlüğü
        self.train_columns = None  # Eğitim sırasında kullanılan tüm sütunların sıralı listesi

    def _temizle(self, df):  # Verideki gereksiz kısımları atan ve log dönüşümü yapan iç metod
        cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
        df = df[cols].copy()  # Sadece modelin beklediği sütunları kopyala
        df['src_bytes'] = np.log1p(df['src_bytes'].astype(float))  # Veri aralığını daraltmak için log(1+x) uygula
        df['dst_bytes'] = np.log1p(df['dst_bytes'].astype(float))  # Veri aralığını daraltmak için log(1+x) uygula
        return df

    def transform(self, df):  # Dışarıdan çağrılan ana dönüştürme fonksiyonu
        df = self._temizle(df)  # Önce temizlik ve log işlemlerini yap
        for col in self.cat_cols:  # Kategorik sütunları tek tek dönüştür
            le = self.encoders[col]  # İlgili sütun için kayıtlı LabelEncoder'ı al
            # Eğer değer eğitimde varsa dönüştür, yoksa (bilinmiyorsa) -1 ata
            df[col] = df[col].astype(str).map(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )
        df = pd.get_dummies(df, columns=self.cat_cols)  # Kategorik sütunları One-Hot formatına çevir
        # Eğitimde olan ama o anki pakette bulunmayan eksik sütunları 0 olarak ekle
        for col in self.train_columns:
            if col not in df.columns:
                df[col] = 0
        # Sütun sıralamasını modelin tam olarak beklediği sıraya getir
        df = df[self.train_columns]
        # Sayısal değerleri (0-1) arasına ölçeklendir
        df[self.train_columns] = self.scaler.transform(df[self.train_columns])
        return df

# --- MODELLERİ YÜKLE  ---
try:
    isleyici = joblib.load('modeller/yeni_isleyici.pkl')  # Ön işlemci nesnesini yükle
    kmeans = joblib.load('modeller/yeni_kmeans.pkl')  # K-Means modelini yükle
    stacking = joblib.load('modeller/yeni_stacking.pkl')  # Stacking modelini yükle
    threshold = np.load('modeller/yeni_esik.npy')  # Kayıtlı anomali eşik değerini yükle
    
    print("="*95)
    print(f"--> [HİBRİT SİSTEM AKTİF] Canlı Trafik Analizi Başladı...")
    print(f"--> Dinamik Eşik (Anomali): {threshold:.4f}")
    print(f"{'ZAMAN':<10} | {'DURUM':<10} | {'KAYNAK IP':<15} | {'PROTOKOL':<8} | {'SKOR':<8}")
    print("-" * 95)
except Exception as e:  # Dosyalar bulunamazsa veya hata oluşursa programı durdur
    print(f"HATA: Modeller yüklenemedi! Lütfen önce yeni eğitim kodunu çalıştırın.\nDetay: {e}")
    sys.exit()

def paket_analiz(pkt):  # Yakalanan her bir ağ paketi için çalışan fonksiyon
    if IP in pkt:  # Paket IP katmanına sahipse işle
        src_ip = pkt[IP].src  # Kaynak IP adresini al
        p_type, flag = "tcp", "SF" # Başlangıç varsayılan değerleri
        
        # Protokol ve Bayrak (Flag) Belirleme Mantığı
        if pkt.haslayer(TCP):  # Eğer paket bir TCP paketi ise
            p_type = "tcp"
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == "S": flag = "S0"  # Bağlantı isteği
            elif tcp_layer.flags == "RA" or tcp_layer.flags == "R": flag = "REJ"  # Reddedildi
        elif pkt.haslayer(ICMP):  # Eğer paket bir ICMP (ping vb.) paketi ise
            p_type = "icmp"
            flag = "SF"
        else:
            p_type = "udp" # Geriye kalanlar (DNS vb.) UDP kabul edilir

        try:
            # Yakalanan paketi sözlük yapısında bir DataFrame'e çevir
            ham_veri = pd.DataFrame([{
                "duration": 0, "protocol_type": p_type, "service": "http", "flag": flag,
                "src_bytes": len(pkt), "dst_bytes": 0, "count": 1, "srv_count": 1
            }])
            
            # DataFrame'i modelin anlayacağı formata (0-1, sayısal) dönüştür
            islenmis = isleyici.transform(ham_veri)
            
            # 1. Stacking Modeli Tahmini (Saldırı mı?)
            stack_pred = stacking.predict(islenmis)[0]
            
            # 2. K-Means Mesafesi Hesapla (Anomali mi?)
            dist = np.min(kmeans.transform(islenmis), axis=1)[0]
            kmeans_pred = 1 if dist > threshold else 0  # Mesafe eşikten büyükse 1 (saldırı) kabul et

            # Hibrit Karar: Eğer iki modelden biri bile saldırı derse uyarıyı bas
            zaman = datetime.now().strftime('%H:%M:%S')
            if stack_pred == 1 or kmeans_pred == 1:
                durum = "SALDIRI!!"
                print(f"{zaman:<10} | {durum:<10} | {src_ip:<15} | {p_type.upper():<8} | {dist:.4f}")
            
        except Exception as e:
            # Analiz sırasında hata oluşursa (bilinmeyen protokol vb.) sessizce atla
            pass

if __name__ == "__main__":
    interfaces = get_windows_if_list()  # Mevcut ağ kartlarını listele
   
    # Kullanılacak ağ kartı indeksi (Hangi kart aktifse o seçilmeli, örnek: 6)
    secim = 6 
    secili_kart = interfaces[secim]
    
    target_iface = None
    # Windows arayüz ismi ile Scapy arayüz ismini eşleştir
    for iface in conf.ifaces.values():
        if secili_kart['name'] == iface.name or secili_kart['description'] in iface.description:
            target_iface = iface
            break
            
    print(f"--> {secili_kart['description']} dinleniyor...\n")
    # Ağ trafiğini canlı olarak dinlemeye başla (IP paketlerini filtrele ve paket_analiz'e gönder)
    sniff(iface=target_iface or secili_kart['name'], filter="ip", prn=paket_analiz, store=0)