import pandas as pd
import numpy as np
import joblib
import time
import sys
import os

# =========================
# GÜNCEL VERİ ÖN İŞLEYİCİ SINIFI
# (Eğitim kodundakiyle birebir aynı olmalıdır)
# =========================
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

# Pickle yüklemesi için bu sınıfın global alanda (burada) olması şarttır.
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

# --- MODELLERİ YÜKLE ---
try:
    p_isleyici = 'modeller/yeni_isleyici.pkl' if os.path.exists('modeller/yeni_isleyici.pkl') else 'modeller/isleyici.pkl'
    p_kmeans = 'modeller/yeni_kmeans.pkl' if os.path.exists('modeller/yeni_kmeans.pkl') else 'modeller/kmeans.pkl'
    p_stacking = 'modeller/yeni_stacking.pkl' if os.path.exists('modeller/yeni_stacking.pkl') else 'modeller/stacking.pkl'
    p_esik = 'modeller/yeni_esik.npy' if os.path.exists('modeller/yeni_esik.npy') else 'modeller/esik.npy'

    isleyici = joblib.load(p_isleyici)
    kmeans = joblib.load(p_kmeans)
    stacking = joblib.load(p_stacking)
    threshold = float(np.load(p_esik))
    
    print("\n" + "="*70)
    print(f"🚀 IDS HİBRİT MODEL SİMÜLASYONU BAŞLATILDI")
    print(f"📡 Sistem Anomali Eşiği: {threshold:.4f}")
    print("="*70 + "\n")
except Exception as e:
    print(f"❌ HATA: Modeller yüklenemedi! Detay: {e}")
    sys.exit()

def test_et(senaryo_adi, p_type, flag, src_bytes, count, service="http"):
    test_data = pd.DataFrame([{
        "duration": 0, "protocol_type": p_type, "service": service, "flag": flag,
        "src_bytes": src_bytes, "dst_bytes": 0, "count": count, "srv_count": count
    }])

    try:
        islenmis = isleyici.transform(test_data)
        stack_pred = stacking.predict(islenmis)[0]
        dist = np.min(kmeans.transform(islenmis), axis=1)[0]
        
        final_karar = "🔴 SALDIRI!!" if (stack_pred == 1 or dist > threshold) else "🟢 NORMAL"
        simge = "🔴" if "SALDIRI" in final_karar else "🟢"
        
        print(f"📋 Senaryo       : {senaryo_adi}")
        print(f"📊 Veri Profili   : {p_type.upper()} | {flag} | Boyut: {src_bytes}")
        print(f"🤖 Karar         : {final_karar} (Skor: {dist:.4f})")
        print("-" * 70)
    except Exception as e:
        print(f"⚠️ Hata: {e}")

if __name__ == "__main__":
    test_et("Normal Web", "tcp", "SF", 250, 1)
    test_et("SYN Flood", "tcp", "S0", 0, 500)
    test_et("Büyük Paket", "icmp", "SF", 65000, 1)