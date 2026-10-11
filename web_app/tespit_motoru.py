import pandas as pd
import numpy as np
import joblib
import sys
import os
import requests
from scapy.all import sniff, IP, TCP, ICMP, conf
from scapy.arch.windows import get_windows_if_list
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import warnings
from collections import defaultdict
import time

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

isleyici = None
kmeans = None
stacking = None
threshold = None

def load_models():
    global isleyici, kmeans, stacking, threshold
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    isleyici = joblib.load(os.path.join(base_dir, 'modeller', 'yeni_isleyici.pkl'))
    kmeans = joblib.load(os.path.join(base_dir, 'modeller', 'yeni_kmeans.pkl'))
    stacking = joblib.load(os.path.join(base_dir, 'modeller', 'yeni_stacking.pkl'))
    threshold = np.load(os.path.join(base_dir, 'modeller', 'yeni_esik.npy'))

import ipaddress

anomali_sayaci = defaultdict(int)
ip_lokasyon_onbellek = {}
SON_SIFIRLAMA_ZAMANI = time.time()
ESIK_DEGERI = 100
cb_trafik = None
cb_alarm = None

def lokasyon_bul(ip):
    if ip in ip_lokasyon_onbellek:
        return ip_lokasyon_onbellek[ip]
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
            loc = {"ulke": "Yerel Ag", "kod": "TR", "sehir": "Yerel"}
            ip_lokasyon_onbellek[ip] = loc
            return loc
        r = requests.get(f"http://ip-api.com/json/{parsed}", timeout=2)
        veri = r.json()
        if veri.get("status") == "success":
            loc = {"ulke": veri.get("country"), "kod": veri.get("countryCode"), "sehir": veri.get("city")}
            ip_lokasyon_onbellek[ip] = loc
            return loc
    except:
        pass
    loc = {"ulke": "Bilinmiyor", "kod": "UN", "sehir": "Bilinmiyor"}
    ip_lokasyon_onbellek[ip] = loc
    return loc

def paket_analiz(pkt):
    global SON_SIFIRLAMA_ZAMANI
    su_an = time.time()
    
    if su_an - SON_SIFIRLAMA_ZAMANI > 5:
        anomali_sayaci.clear()
        SON_SIFIRLAMA_ZAMANI = su_an

    if IP in pkt:
        src_ip = pkt[IP].src
        p_type = "udp"
        flag = "SF"
        
        if pkt.haslayer(TCP):
            p_type = "tcp"
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == "S": flag = "S0"
            elif tcp_layer.flags == "RA" or tcp_layer.flags == "R": flag = "REJ"
        elif pkt.haslayer(ICMP):
            p_type = "icmp"

        try:
            ham_veri = pd.DataFrame([{
                "duration": 0, "protocol_type": p_type, "service": "http", "flag": flag,
                "src_bytes": len(pkt), "dst_bytes": 0, "count": 1, "srv_count": 1
            }])
            
            islenmis = isleyici.transform(ham_veri)
            stack_pred = stacking.predict(islenmis)[0]
            dist = np.min(kmeans.transform(islenmis), axis=1)[0]
            kmeans_pred = 1 if dist > threshold else 0

            is_anomali = False
            if stack_pred == 1 or kmeans_pred == 1:
                anomali_sayaci[src_ip] += 1
                is_anomali = True
            else:
                anomali_sayaci[src_ip] = max(0, anomali_sayaci[src_ip] - 1)

            veri = {
                "ip": src_ip,
                "protokol": p_type,
                "anomali": is_anomali,
                "skor": float(dist),
                "ardisik_anomali": anomali_sayaci[src_ip]
            }
            if cb_trafik:
                cb_trafik(veri)
            
            if anomali_sayaci[src_ip] >= ESIK_DEGERI:
                loc = lokasyon_bul(src_ip)
                alarm_verisi = {
                    "ip": src_ip,
                    "sayi": anomali_sayaci[src_ip],
                    "lokasyon": loc,
                    "zaman": datetime.now().strftime('%H:%M:%S')
                }
                if cb_alarm:
                    cb_alarm(alarm_verisi)
                anomali_sayaci[src_ip] = 0

        except:
            pass

def baslat(trafik_callback, alarm_callback):
    global cb_trafik, cb_alarm
    cb_trafik = trafik_callback
    cb_alarm = alarm_callback
    load_models()
    interfaces = get_windows_if_list()
    secim = 6 
    secili_kart = interfaces[secim]
    target_iface = None
    for iface in conf.ifaces.values():
        if secili_kart['name'] == iface.name or secili_kart['description'] in iface.description:
            target_iface = iface
            break
    sniff(iface=target_iface or secili_kart['name'], filter="ip", prn=paket_analiz, store=0)
