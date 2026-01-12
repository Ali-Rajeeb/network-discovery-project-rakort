\# Network Discovery Project



Bu proje verilen IP bloğu üzerinde:

\- Canlı host keşfi

\- Port/servis keşfi (nmap)

\- Dataset üretimi (JSONL)

\- Bulgu (finding) + 0–10 risk skoru

\- Rapor + grafik üretimi

işlemlerini uçtan uca otomatik yapar.



\## Çıktılar

\- reports/report.md

\- reports/figures/\*.png

\- dataset/services.jsonl

\- dataset/findings.jsonl





# Network Discovery - Farklı IP Listesi Pipeline (PowerShell)
# Klasör: C:\Users\assea\network-discovery

1) Proje klasörüne gir:
cd C:\Users\assea\network-discovery

2) IP listesini oluştur:
notepad targets\custom_targets.txt
(1 satır = 1 IP)

3) IP sayısını kontrol et:
(Get-Content targets\custom_targets.txt).Count

4) Alive scan çalıştır:
python tools\alive_scan.py --targets targets\custom_targets.txt --out dataset\alive_hosts_custom.jsonl --timeout-ms 400 --threads 60

5) Alive IP’leri ayıkla:
Select-String -Path dataset\alive_hosts_custom.jsonl -Pattern '"alive": true' | ForEach-Object { ($_.Line | ConvertFrom-Json).ip } | Set-Content -Encoding ascii dataset\alive_ips_custom.txt

6) Alive IP’leri kontrol et:
Get-Content dataset\alive_ips_custom.txt

7) Nmap (alive IP’lerde):
nmap -sS -sV -T4 -Pn -iL dataset\alive_ips_custom.txt --top-ports 200 -oN raw\nmap_custom.txt -oX raw\nmap_custom.xml

8) XML -> services dataset:
python tools\parse_nmap_xml.py --xml raw\nmap_custom.xml --out dataset\services_custom.jsonl

9) Findings üret:
python tools\findings_engine.py --services dataset\services_custom.jsonl --out dataset\findings_custom.jsonl

10) Rapor üret:
python tools\make_report.py --services dataset\services_custom.jsonl --findings dataset\findings_custom.jsonl --out reports\report_custom.md

11) Raporu aç:
notepad reports\report_custom.md

12) Grafikler (opsiyonel):
copy dataset\services_custom.jsonl dataset\services.jsonl /Y
copy dataset\findings_custom.jsonl dataset\findings.jsonl /Y
python tools\make_charts.py
explorer reports\figures

 Eğer alive listesi boş çıkarsa (ping kapalı):
 Direct Nmap:
 nmap -sS -sV -T4 -Pn -iL targets\custom_targets.txt --top-ports 200 -oN raw\nmap_custom.txt -oX raw\nmap_custom.xml

