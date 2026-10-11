@echo off
chcp 65001 > nul
echo =======================================================
echo   YAPAY ZEKA DESTEKLI IDS/IPS SALDIRI SIMULASYONU
echo =======================================================
echo Hedef: 8.8.8.8:80 (Scapy SYN Flood DDoS)
echo.

where python >nul 2>nul
if %errorlevel% equ 0 (
    python GERCEK_SALDIRI.py
    pause
    exit /b
)

where py >nul 2>nul
if %errorlevel% equ 0 (
    py GERCEK_SALDIRI.py
    pause
    exit /b
)

if exist "C:\Users\tayyi\AppData\Local\Programs\Python\Python315\python.exe" (
    "C:\Users\tayyi\AppData\Local\Programs\Python\Python315\python.exe" GERCEK_SALDIRI.py
    pause
    exit /b
)

echo [HATA] Sisteminizde Python bulunamadi! Lutfen Python'i yukleyin veya PATH ortam degiskenine ekleyin.
pause
