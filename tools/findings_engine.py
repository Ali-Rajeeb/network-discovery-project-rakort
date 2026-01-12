import argparse
import json
from datetime import datetime
from pathlib import Path

def make_finding(fid, title, why, rec, score, r, now):
    return {
        "finding_id": fid,
        "ip": r.get("ip"),
        "hostname": r.get("hostname"),
        "proto": r.get("proto"),
        "port": r.get("port"),
        "service_name": r.get("service_name"),
        "product": r.get("product"),
        "version": r.get("version"),
        "evidence": {
            "extrainfo": r.get("extrainfo"),
            "tunnel": r.get("tunnel"),
            "cpes": r.get("cpes"),
        },
        "title": title,
        "why": why,
        "recommendation": rec,
        "severity_0_10": score,
        "generated_at": now
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--services", default="dataset/services.jsonl")
    ap.add_argument("--out", default="dataset/findings.jsonl")
    args = ap.parse_args()

    in_path = Path(args.services)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow().isoformat() + "Z"

    findings = []
    seen = set()

    with in_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)

            ip = r.get("ip")
            port = r.get("port")
            svc = r.get("service_name")
            product = (r.get("product") or "").lower()
            tunnel = r.get("tunnel")

            def add(fid, title, why, rec, score):
                key = (fid, ip, r.get("proto"), port)
                if key in seen:
                    return
                seen.add(key)
                findings.append(make_finding(fid, title, why, rec, score, r, now))

            # --- Kurallar ---
            if port == 1900 or svc == "upnp":
                add("UPNP_EXPOSED",
                    "UPnP servisi açık",
                    "UPnP saldırı yüzeyini büyütebilir; yanlış yapılandırmada risk artar.",
                    "Kullanmıyorsanız kapatın. Gerekliyse sadece LAN ile sınırlandırın.",
                    7)

            if port in (80, 8080) and svc in ("http", "http-proxy"):
                add("HTTP_MGMT",
                    "HTTP tabanlı arayüz/servis açık",
                    "Web arayüzleri varsayılan/zayıf parola ile riskli olabilir.",
                    "Sadece LAN'dan erişim, güçlü parola, mümkünse HTTPS kullanın.",
                    6)

            if port == 443 and svc == "https":
                add("HTTPS_MGMT",
                    "HTTPS servisi açık",
                    "HTTPS iyi ama yine de yönetim arayüzü olabilir; hesap güvenliği önemli.",
                    "Güçlü parola/2FA varsa açın, yönetimi LAN ile sınırlandırın.",
                    3)

            if port == 22 and svc == "ssh":
                add("SSH_EXPOSED",
                    "SSH servisi açık",
                    "Brute-force denemelerine hedef olabilir.",
                    "Gerekmiyorsa kapatın. Gerekiyorsa güçlü parola/anahtar ve IP kısıtı uygulayın.",
                    5)

            if port in (139, 445) and (svc in ("netbios-ssn", "microsoft-ds") or "samba" in product):
                add("SMB_NETBIOS",
                    "SMB/NetBIOS (dosya paylaşımı) açık",
                    "LAN içinde yaygın ama saldırılarda sık hedef olur.",
                    "Gereksizse kapatın. Gerekliyse paylaşım izinlerini daraltın, misafir erişimi kapatın.",
                    6)

            if port == 3306 or svc == "mysql":
                add("MYSQL_EXPOSED",
                    "MySQL portu açık",
                    "DB portu açık olunca brute-force ve zafiyet taramalarına hedef olur.",
                    "Sadece gereken IP'lere izin verin (firewall/bind). Güçlü parola ve güncel sürüm.",
                    7)

            if port == 902 or svc == "vmware-auth":
                add("VMWARE_AUTH",
                    "VMware Authentication servisi açık",
                    "Sanallaştırma/management servisleri hedef olabilir.",
                    "Gereksizse kapatın; gerekliyse sadece lokal/izinli IP'lere kısıtlayın.",
                    6)

            if port == 135 or svc == "msrpc":
                add("WINDOWS_RPC",
                    "Windows RPC (135) açık",
                    "RPC normal olabilir ama ağ içi keşif/istismar zincirlerinde hedef olabilir.",
                    "Gerekmiyorsa firewall ile kısıtlayın.",
                    5)

            if tunnel == "ssl" and port == 7070:
                add("SSL_UNKNOWN_7070",
                    "7070 üzerinde TLS/SSL servis açık (servis belirsiz)",
                    "Servis net değilse yanlış yapılandırma/unutulmuş servis riski olabilir.",
                    "Bu portu hangi uygulamanın açtığını doğrulayın; gereksizse kapatın.",
                    5)

            if port == 53 and svc == "domain":
                add("DNS_EXPOSED",
                    "DNS servisi açık",
                    "DNS genelde normaldir ama yanlış konfigürasyon (açık resolver) risk doğurabilir.",
                    "DNS sadece LAN istemcilerine hizmet vermeli; dışarıya açık resolver olmamalı.",
                    4)

    # Çıktıyı yaz (dosya her durumda oluşturulur)
    with out_path.open("w", encoding="utf-8-sig") as fo:

        for it in findings:
            fo.write(json.dumps(it, ensure_ascii=False) + "\n")

    avg = (sum(x["severity_0_10"] for x in findings) / len(findings)) if findings else 0.0
    print("OK ✅ Findings generated.")
    print(f"Total findings: {len(findings)} | Avg severity: {avg:.2f}")
    print(f"Wrote: {out_path}")

if __name__ == "__main__":
    main()
