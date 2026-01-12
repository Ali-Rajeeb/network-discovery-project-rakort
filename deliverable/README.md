\# Network Discovery Project



\## Amaç

Verilen IP bloğundaki canlı hostları, açık portları ve servisleri tespit etmek;

elde edilen veriyi normalize ederek dataset üretmek; bulgu (finding) ve 0–10 risk skoru çıkarıp raporlamak.



\## Üretilen Çıktılar

\- dataset/services.jsonl : açık port/servis envanteri (ip, port, servis, ürün, versiyon)

\- dataset/findings.jsonl : kurallarla üretilmiş bulgular + 0–10 risk skorları

\- reports/report.md : özet + host bazlı servisler + bulgular + öneriler

\- reports/figures/\*.png : istatistik grafikleri (top ports, top services, host risk)

\- raw/nmap\_top.\* : nmap ham çıktıları

\- meta/\*.json : hedef listesi ve tarama özetleri



\## Çalıştırma Sırası

1\) Targets üret: tools/gen\_targets.py

2\) Alive scan: tools/alive\_scan.py

3\) Nmap tarama: (komut satırı)

4\) XML parse: tools/parse\_nmap\_xml.py

5\) Findings üret: tools/findings\_engine.py

6\) Rapor: tools/make\_report.py

7\) Grafik: tools/make\_charts.py



