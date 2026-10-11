import pandas as pd
import numpy as np
import joblib
import sys
from scapy.all import sniff, IP, TCP, ICMP, conf
from scapy.arch.windows import get_windows_if_list
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import warnings

warnings.simplefilter(action='ignore', category=pd.errors.PerformanceWarning)
warnings.filterwarnings("ignore")

class VeriOnIsleyici:
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.cat_cols = ['protocol_type', 'service', 'flag']
        self.encoders = {}
        self.train_columns = None

    def _temizle(self, df):
        cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
        df = df[cols].copy()
        df['src_bytes'] = np.log1p(df['src_bytes'].astype(float))
        df['dst_bytes'] = np.log1p(df['dst_bytes'].astype(float))
        return df

    def transform(self, df):
        df = self._temizle(df)
        for col in self.cat_cols:
            le = self.encoders[col]
            df[col] = df[col].astype(str).map(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )
        df = pd.get_dummies(df, columns=self.cat_cols)
        for col in self.train_columns:
            if col not in df.columns:
                df[col] = 0
        df = df[self.train_columns]
        df[self.train_columns] = self.scaler.transform(df[self.train_columns])
        return df

try:
    isleyici = joblib.load('modeller/yeni_isleyici.pkl')
    kmeans = joblib.load('modeller/yeni_kmeans.pkl')
    stacking = joblib.load('modeller/yeni_stacking.pkl')
    threshold = np.load('modeller/yeni_esik.npy')
    
    print("="*95)
    print(f"--> [HİBRİT SİSTEM AKTİF] Canlı Trafik Analizi Başladı...")
    print(f"--> Dinamik Eşik (Anomali): {threshold:.4f}")
    print(f"{'ZAMAN':<10} | {'DURUM':<10} | {'KAYNAK IP':<15} | {'PROTOKOL':<8} | {'SKOR':<8}")
    print("-" * 95)
except Exception as e:
    print(f"HATA: {e}")
    sys.exit()

def paket_analiz(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        p_type, flag = "tcp", "SF"
        
        if pkt.haslayer(TCP):
            p_type = "tcp"
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == "S": flag = "S0"
            elif tcp_layer.flags == "RA" or tcp_layer.flags == "R": flag = "REJ"
        elif pkt.haslayer(ICMP):
            p_type = "icmp"
            flag = "SF"

        try:
            ham_veri = pd.DataFrame([{
                "duration": 0, "protocol_type": p_type, "service": "http", "flag": flag,
                "src_bytes": len(pkt), "dst_bytes": 0, "count": 1, "srv_count": 1
            }])
            
            islenmis = isleyici.transform(ham_veri)
            stack_pred = stacking.predict(islenmis)[0]
            dist = np.min(kmeans.transform(islenmis), axis=1)[0]
            kmeans_pred = 1 if dist > threshold else 0

            zaman = datetime.now().strftime('%H:%M:%S')
            if stack_pred == 1 or kmeans_pred == 1:
                durum = "SALDIRI!!"
                print(f"{zaman:<10} | {durum:<10} | {src_ip:<15} | {p_type.upper():<8} | {dist:.4f}")
            
        except:
            pass

if __name__ == "__main__":
    interfaces = get_windows_if_list()
    secilen_id_listesi = [1, 6]
    target_names = []
    
    for idx in secilen_id_listesi:
        if idx < len(interfaces):
            desc = interfaces[idx]['description']
            for iface in conf.ifaces.values():
                if desc in iface.description:
                    target_names.append(iface.name)
                    break
            
    sniff(iface=target_names, filter="tcp or icmp", prn=paket_analiz, store=0)