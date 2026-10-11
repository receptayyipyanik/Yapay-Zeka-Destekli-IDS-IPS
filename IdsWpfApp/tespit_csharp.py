import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import joblib
import sys
import os
import requests
import json
import ipaddress
from collections import defaultdict
import time
import threading
from queue import Queue
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import sklearn.ensemble._stacking
import sklearn.ensemble._forest
import sklearn.tree._classes
import sklearn.linear_model._logistic
import sklearn.cluster._kmeans
import sklearn.neighbors._classification
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from scapy.arch.windows import get_windows_if_list

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

# Pickle yuklenirken __main__.VeriOnIsleyici referansini garantiye al
setattr(sys.modules['__main__'], 'VeriOnIsleyici', VeriOnIsleyici)

# Model Dosyalari ve Yukleme
exec_dir = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
candidate_dirs = [
    os.path.join(os.path.dirname(exec_dir), 'modeller'),
    os.path.join(exec_dir, 'modeller'),
    os.path.join(os.getcwd(), 'modeller'),
    os.path.join(os.path.dirname(os.getcwd()), 'modeller'),
    os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), 'modeller'),
    os.path.abspath('modeller')
]
modeller_dir = next((d for d in candidate_dirs if os.path.exists(d)), os.path.abspath('modeller'))

isleyici = joblib.load(os.path.join(modeller_dir, 'yeni_isleyici.pkl'))
kmeans = joblib.load(os.path.join(modeller_dir, 'yeni_kmeans.pkl'))
stacking = joblib.load(os.path.join(modeller_dir, 'yeni_stacking.pkl'))
threshold = float(np.load(os.path.join(modeller_dir, 'yeni_esik.npy')))

# Parametreler ve Sayaclar
ESIK_DEGERI = 25  # Alarm tetikleme anomali paketi esigi
anomali_sayaci = defaultdict(int)
ip_lokasyon_onbellek = {}
SON_DECAY_ZAMANI = time.time()
SON_STATS_ZAMANI = time.time()
total_packets = 0
anomalous_packets = 0

def belirle_servis(p_type, sport, dport):
    port = dport if dport < 1024 else sport
    if p_type == "tcp":
        if port in (80, 8080):
            return "http"
        elif port == 443:
            return "http_443"
        elif port == 53:
            return "domain"
        elif port == 21:
            return "ftp"
        elif port == 22:
            return "ssh"
        elif port == 25:
            return "smtp"
        else:
            return "other"
    elif p_type == "udp":
        if port == 53:
            return "domain_u"
        elif port == 123:
            return "ntp_u"
        else:
            return "other"
    elif p_type == "icmp":
        return "eco_i"
    return "other"

class FlowTracker:
    def __init__(self):
        self.flows = {}
        self.ip_history = defaultdict(list)
        self.srv_history = defaultdict(list)
        self.last_cleanup = time.time()

    def add_packet(self, pkt, su_an):
        if IP not in pkt:
            return None
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = 0
        dport = 0
        flag = "SF"
        p_type = "icmp"

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            p_type = "tcp"
            f = str(pkt[TCP].flags)
            if f == "S":
                flag = "S0"
            elif "R" in f:
                flag = "REJ"
            else:
                flag = "SF"
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            p_type = "udp"
            flag = "SF"

        flow_key = (src, dst, sport, dport, p_type)
        flow_key_rev = (dst, src, dport, sport, p_type)

        # 2 saniyede bir eski baglantilari (10 sn oncesini) temizle
        if su_an - self.last_cleanup > 2.0:
            for k in list(self.ip_history.keys()):
                self.ip_history[k] = [t for t in self.ip_history[k] if su_an - t < 10.0]
                if not self.ip_history[k]:
                    del self.ip_history[k]
            for k in list(self.srv_history.keys()):
                self.srv_history[k] = [t for t in self.srv_history[k] if su_an - t < 10.0]
                if not self.srv_history[k]:
                    del self.srv_history[k]
            if len(self.flows) > 5000:
                self.flows = {k: v for k, v in self.flows.items() if su_an - v['start'] < 60.0}
            self.last_cleanup = su_an

        # IP ve port gecmisini guncelle
        self.ip_history[src].append(su_an)
        self.srv_history[(src, dport)].append(su_an)

        service = belirle_servis(p_type, sport, dport)

        if flow_key in self.flows:
            flow = self.flows[flow_key]
            flow['duration'] = su_an - flow['start']
            flow['src_bytes'] += len(pkt[IP].payload)
            if flag != "SF":
                flow['flag'] = flag
        elif flow_key_rev in self.flows:
            flow = self.flows[flow_key_rev]
            flow['duration'] = su_an - flow['start']
            flow['dst_bytes'] += len(pkt[IP].payload)
            if flow['flag'] == "S0":
                flow['flag'] = "SF"
        else:
            flow = {
                'start': su_an, 'duration': 0.0, 'src_bytes': len(pkt[IP].payload), 'dst_bytes': 0,
                'flag': flag, 'p_type': p_type, 'service': service, 'src': src
            }
            self.flows[flow_key] = flow

        count = len(self.ip_history[src])
        srv_count = len(self.srv_history[(src, dport)])
        return flow, count, srv_count

tracker = FlowTracker()
paket_kuyrugu = Queue(maxsize=100000)

def lokasyon_bul(ip):
    if ip in ip_lokasyon_onbellek:
        return ip_lokasyon_onbellek[ip]
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
            loc = "Yerel Ag (Local)"
            ip_lokasyon_onbellek[ip] = loc
            return loc
        r = requests.get(f"http://ip-api.com/json/{parsed}", timeout=2)
        veri = r.json()
        if veri.get("status") == "success":
            loc = f"{veri.get('countryCode')}/{veri.get('city')}"
            ip_lokasyon_onbellek[ip] = loc
            return loc
    except:
        pass
    loc = "Bilinmiyor"
    ip_lokasyon_onbellek[ip] = loc
    return loc

def analiz_motoru():
    global SON_DECAY_ZAMANI, SON_STATS_ZAMANI, total_packets, anomalous_packets
    while True:
        pkt = paket_kuyrugu.get()
        if pkt is None:
            break

        pkts = [pkt]
        # Hizli batch isleme: kuyruktaki diger paketleri de topla (maks 100 paket)
        while len(pkts) < 100:
            try:
                p = paket_kuyrugu.get_nowait()
                if p is None:
                    break
                pkts.append(p)
            except:
                break

        su_an = time.time()
        total_packets += len(pkts)

        # Periyodik sayac sonumlendirme (10 saniyede bir hafif azalt)
        if su_an - SON_DECAY_ZAMANI > 10.0:
            for k in list(anomali_sayaci.keys()):
                anomali_sayaci[k] = max(0, anomali_sayaci[k] - 5)
                if anomali_sayaci[k] == 0:
                    del anomali_sayaci[k]
            SON_DECAY_ZAMANI = su_an

        batch_rows = []
        batch_meta = []  # (src, count)

        for p in pkts:
            res = tracker.add_packet(p, su_an)
            if not res:
                continue
            flow, count, srv_count = res
            batch_rows.append({
                "duration": flow['duration'],
                "protocol_type": flow['p_type'],
                "service": flow['service'],
                "flag": flow['flag'],
                "src_bytes": flow['src_bytes'],
                "dst_bytes": flow['dst_bytes'],
                "count": count,
                "srv_count": srv_count
            })
            batch_meta.append((flow['src'], count))

        if batch_rows:
            try:
                df = pd.DataFrame(batch_rows)
                islenmis = isleyici.transform(df)
                stack_preds = stacking.predict(islenmis)
                dists = np.min(kmeans.transform(islenmis), axis=1)
                kmeans_preds = (dists > threshold).astype(int)

                for i in range(len(batch_rows)):
                    sp = stack_preds[i]
                    kp = kmeans_preds[i]
                    src, cnt = batch_meta[i]
                    flag = batch_rows[i]['flag']

                    # Anomali kurali: ML modelinin kesin tespiti (Stacking + KMeans veya Saldiri Bayragi)
                    # Normal arka plan trafigi (flag=SF) asla anomali sayilmaz
                    is_anomali = (sp == 1 and flag in ['S0', 'REJ']) or (sp == 1 and kp == 1 and flag != 'SF')

                    if is_anomali:
                        anomalous_packets += 1
                        anomali_sayaci[src] += 1
                    else:
                        if src in anomali_sayaci:
                            anomali_sayaci[src] = max(0, anomali_sayaci[src] - 1)

                    if anomali_sayaci[src] >= ESIK_DEGERI:
                        loc = lokasyon_bul(src)
                        zaman = datetime.now().strftime('%H:%M:%S')
                        print(json.dumps({
                            "type": "alarm",
                            "ip": src,
                            "count": anomali_sayaci[src],
                            "loc": loc,
                            "time": zaman
                        }))
                        sys.stdout.flush()
                        anomali_sayaci[src] = 0

            except Exception as e:
                with open("error_log.txt", "a") as f:
                    f.write(f"Batch hatasi: {e}\n")

        # Her saniye istatistik yayinla
        if su_an - SON_STATS_ZAMANI >= 1.0:
            print(json.dumps({
                "type": "stats",
                "total": total_packets,
                "anomalous": anomalous_packets
            }))
            sys.stdout.flush()
            SON_STATS_ZAMANI = su_an

def paket_yakalayici(pkt):
    try:
        paket_kuyrugu.put_nowait(pkt)
    except:
        pass

if __name__ == '__main__':
    analiz_thread = threading.Thread(target=analiz_motoru, daemon=True)
    analiz_thread.start()

    print(json.dumps({"type": "status", "message": "Python AI Motoru Baslatildi, Dinleniyor..."}))
    sys.stdout.flush()

    interfaces = get_windows_if_list()
    route_iface = conf.route.route('8.8.8.8')[0]
    target_ifaces = [route_iface]

    for iface in interfaces:
        if "Loopback" in iface.get('description', '') or "Loopback" in iface.get('name', ''):
            target_ifaces.append(iface['name'])
            break

    sniff(iface=target_ifaces, filter="ip", prn=paket_yakalayici, store=0)
