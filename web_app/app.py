import os
import time
import subprocess
import ipaddress
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from threading import Thread
import tespit_motoru

app = Flask(__name__)
# OWASP A07 / A02: Guvenli anahtar yonetimi (ortam degiskeni veya rastgele anahtar)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
socketio = SocketIO(app, async_mode='threading')

def kural_ekle(ip_adresi):
    """
    OWASP A03 Command Injection Onlemi:
    1. IP adresini 'ipaddress' moduluyle katı dogrulamaya tabi tutar.
    2. shell=False kullanarak arguman dizisi ile netsh komutunu calistirir.
    3. Loopback ve broadcast adreslerini engelleyerek self-DoS saldirilarini onler.
    """
    try:
        parsed_ip = ipaddress.ip_address(ip_adresi.strip())
        if parsed_ip.is_loopback or parsed_ip.is_unspecified or parsed_ip.is_multicast:
            return False, "Gecersiz veya yerel IP adresi engellenemez."
        if parsed_ip.is_private and str(parsed_ip).endswith(('.1', '.255')):
            return False, "Yerel ag gecidi veya broadcast IP adresi engellenemez."
        
        safe_ip = str(parsed_ip)
        kural_adi = f"BLOCK_IP_{safe_ip}"
        
        komut_argumanlari = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={kural_adi}", "dir=in", "action=block", f"remoteip={safe_ip}"
        ]
        
        sonuc = subprocess.run(komut_argumanlari, shell=False, capture_output=True, text=True, timeout=5)
        return sonuc.returncode == 0, "Basarili" if sonuc.returncode == 0 else sonuc.stderr
    except ValueError:
        return False, "Gecersiz IP adresi formati."
    except Exception as e:
        return False, str(e)

@app.route('/')
def index():
    return render_template('index.html')

# OWASP A04: State-changing eylemler icin POST destegi ve dogrulama
@app.route('/engelle', methods=['POST'])
def engelle_post():
    data = request.get_json(silent=True) or {}
    ip_adresi = data.get('ip', '')
    basarili, mesaj = kural_ekle(ip_adresi)
    if basarili:
        return jsonify({"status": "success", "ip": ip_adresi})
    return jsonify({"status": "error", "message": mesaj}), 400

@app.route('/engelle/<ip_adresi>', methods=['GET'])
def engelle_get(ip_adresi):
    basarili, mesaj = kural_ekle(ip_adresi)
    if basarili:
        return jsonify({"status": "success", "ip": ip_adresi})
    return jsonify({"status": "error", "message": mesaj}), 400

def trafik_verisi_gonder(veri):
    socketio.emit('trafik_guncelleme', veri)

def alarm_gonder(veri):
    socketio.emit('saldiri_alarmi', veri)

if __name__ == '__main__':
    dinleyici_thread = Thread(target=tespit_motoru.baslat, args=(trafik_verisi_gonder, alarm_gonder))
    dinleyici_thread.daemon = True
    dinleyici_thread.start()
    socketio.run(app, debug=False, host='127.0.0.1', port=5000)
