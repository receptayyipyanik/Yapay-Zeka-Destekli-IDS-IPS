const socket = io();
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Normal Paketler',
            data: [],
            borderColor: '#00ffcc',
            backgroundColor: 'rgba(0, 255, 204, 0.1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true
        }, {
            label: 'Anormal Paketler',
            data: [],
            borderColor: '#ff3366',
            backgroundColor: 'rgba(255, 51, 102, 0.1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                grid: { color: '#1e293b' },
                ticks: { color: '#94a3b8' }
            },
            x: {
                grid: { color: '#1e293b' },
                ticks: { color: '#94a3b8' }
            }
        },
        plugins: {
            legend: {
                labels: { color: '#e2e8f0' }
            }
        },
        animation: {
            duration: 0
        }
    }
});
let totalPackets = 0;
let anomalousPackets = 0;
let blockedIpsCount = 0;
let currentSecond = Math.floor(Date.now() / 1000);
let packetsThisSecondNormal = 0;
let packetsThisSecondAnomalous = 0;
setInterval(() => {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    trafficChart.data.labels.push(timeString);
    trafficChart.data.datasets[0].data.push(packetsThisSecondNormal);
    trafficChart.data.datasets[1].data.push(packetsThisSecondAnomalous);
    if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
        trafficChart.data.datasets[1].data.shift();
    }
    trafficChart.update();
    packetsThisSecondNormal = 0;
    packetsThisSecondAnomalous = 0;
}, 1000);
socket.on('trafik_guncelleme', function(data) {
    totalPackets++;
    document.getElementById('totalPackets').innerText = totalPackets;
    if (data.anomali) {
        anomalousPackets++;
        document.getElementById('anomalousPackets').innerText = anomalousPackets;
        packetsThisSecondAnomalous++;
    } else {
        packetsThisSecondNormal++;
    }
});
socket.on('saldiri_alarmi', function(data) {
    const alertList = document.getElementById('alertList');
    const alertId = 'alert_' + Date.now();
    const div = document.createElement('div');
    div.className = 'alert-item';
    div.id = alertId;
    let locStr = data.lokasyon.ulke + ' / ' + data.lokasyon.sehir;
    div.innerHTML = `
        <span class="alert-ip">${data.ip}</span>
        <div class="alert-details">
            <div>Zaman: ${data.zaman}</div>
            <div>Paket: ${data.sayi} (Ardisik)</div>
            <div>Lokasyon: ${locStr}</div>
        </div>
        <button class="block-btn" onclick="engelleIp('${data.ip}', '${alertId}')">IP'yi Engelle</button>
    `;
    alertList.prepend(div);
    if (alertList.children.length > 50) {
        alertList.removeChild(alertList.lastChild);
    }
});
function engelleIp(ip, alertId) {
    fetch('/engelle/' + ip)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const alertDiv = document.getElementById(alertId);
                if (alertDiv) {
                    alertDiv.classList.add('blocked');
                    alertDiv.querySelector('.alert-details').innerHTML += '<div><b>DURUM: ENGELLENDI</b></div>';
                }
                blockedIpsCount++;
                document.getElementById('blockedIps').innerText = blockedIpsCount;
            }
        });
}
