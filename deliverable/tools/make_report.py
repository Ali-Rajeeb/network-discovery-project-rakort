import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def read_jsonl(path: Path):
    items = []
    # utf-8-sig: BOM varsa otomatik yok sayar
    with path.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--services", default="dataset/services.jsonl")
    ap.add_argument("--findings", default="dataset/findings.jsonl")
    ap.add_argument("--out", default="reports/report.md")
    args = ap.parse_args()

    services_path = Path(args.services)
    findings_path = Path(args.findings)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    services = read_jsonl(services_path)
    findings = read_jsonl(findings_path)

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Host bazlı grupla
    svc_by_host = defaultdict(list)
    for s in services:
        svc_by_host[s["ip"]].append(s)

    find_by_host = defaultdict(list)
    for fnd in findings:
        find_by_host[fnd["ip"]].append(fnd)

    # Genel skorlar
    all_scores = [f["severity_0_10"] for f in findings] if findings else []
    avg_score = sum(all_scores) / len(all_scores) if all_scores else 0.0
    max_score = max(all_scores) if all_scores else 0

    # Host risk skoru: o hosttaki finding skorlarının ortalaması
    host_scores = {}
    for ip, flist in find_by_host.items():
        scores = [x["severity_0_10"] for x in flist]
        host_scores[ip] = sum(scores) / len(scores) if scores else 0.0

    most_risky_host = None
    if host_scores:
        most_risky_host = sorted(host_scores.items(), key=lambda x: x[1], reverse=True)[0]

    # Rapor yaz
    lines = []
    lines.append("# Network Discovery Raporu\n\n")
    lines.append(f"- Oluşturulma zamanı: **{now}**\n")
    lines.append(f"- Toplam host (scan çıktılarına göre): **{len(svc_by_host)}**\n")
    lines.append(f"- Toplam açık servis kaydı: **{len(services)}**\n")
    lines.append(f"- Toplam bulgu (finding): **{len(findings)}**\n")
    lines.append(f"- Ortalama risk skoru: **{avg_score:.2f}/10**\n")
    lines.append(f"- En yüksek tekil bulgu skoru: **{max_score}/10**\n")
    if most_risky_host:
        lines.append(f"- En riskli host (ortalama): **{most_risky_host[0]} ({most_risky_host[1]:.2f}/10)**\n")
    lines.append("\n---\n\n")

    # Host bazlı detay
    for ip in sorted(svc_by_host.keys()):
        host_services = sorted(svc_by_host[ip], key=lambda x: x["port"])
        host_findings = sorted(find_by_host.get(ip, []), key=lambda x: x["severity_0_10"], reverse=True)

        hn = None
        for s in host_services:
            if s.get("hostname"):
                hn = s["hostname"]
                break

        lines.append(f"## Host: {ip}" + (f" ({hn})" if hn else "") + "\n\n")
        lines.append(f"- Açık port sayısı: **{len(host_services)}**\n")
        if ip in host_scores:
            lines.append(f"- Host risk ortalaması: **{host_scores[ip]:.2f}/10**\n")
        lines.append("\n### Açık Portlar / Servisler\n\n")
        lines.append("| Port | Proto | Servis | Ürün | Versiyon | Not |\n")
        lines.append("|---:|:---:|---|---|---|---|\n")
        for s in host_services:
            lines.append(
                f"| {s['port']} | {s['proto']} | {s.get('service_name') or ''} | {s.get('product') or ''} | {s.get('version') or ''} | {s.get('extrainfo') or ''} |\n"
            )

        lines.append("\n### Bulgular (Findings)\n\n")
        if not host_findings:
            lines.append("_Bu host için bulgu üretilmedi._\n\n")
        else:
            for fnd in host_findings:
                lines.append(f"**[{fnd['severity_0_10']}/10] {fnd['title']}**  \n")
                lines.append(f"- Port/Servis: `{fnd['proto']}/{fnd['port']} {fnd.get('service_name') or ''}`  \n")
                lines.append(f"- Neden: {fnd['why']}  \n")
                lines.append(f"- Öneri: {fnd['recommendation']}  \n\n")

        lines.append("\n---\n\n")

    out_path.write_text("".join(lines), encoding="utf-8")
    print("OK ✅ Report generated:", out_path)

if __name__ == "__main__":
    main()
