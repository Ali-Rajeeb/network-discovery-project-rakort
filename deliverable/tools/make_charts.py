import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt

def read_jsonl(path: Path, encoding="utf-8-sig"):
    items = []
    with path.open("r", encoding=encoding) as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items

def save_bar(labels, values, title, outpath: Path):
    plt.figure()
    plt.bar(labels, values)
    plt.title(title)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(outpath)
    plt.close()

def main():
    services = read_jsonl(Path("dataset/services.jsonl"), encoding="utf-8-sig")
    findings = read_jsonl(Path("dataset/findings.jsonl"), encoding="utf-8-sig")

    outdir = Path("reports/figures")
    outdir.mkdir(parents=True, exist_ok=True)

    # Top ports
    port_counts = Counter([s["port"] for s in services])
    top_ports = port_counts.most_common(10)
    save_bar([str(p) for p, c in top_ports], [c for p, c in top_ports],
             "Top 10 Open Ports", outdir / "top_ports.png")

    # Top services
    svc_counts = Counter([s.get("service_name") or "unknown" for s in services])
    top_svcs = svc_counts.most_common(10)
    save_bar([name for name, c in top_svcs], [c for name, c in top_svcs],
             "Top 10 Service Names", outdir / "top_services.png")

    # Host risk (avg severity per host)
    by_host = defaultdict(list)
    for f in findings:
        by_host[f["ip"]].append(f["severity_0_10"])
    host_avg = {ip: sum(v)/len(v) for ip, v in by_host.items()}
    ordered = sorted(host_avg.items(), key=lambda x: x[1], reverse=True)

    save_bar([ip for ip, _ in ordered], [v for _, v in ordered],
             "Average Risk Score per Host", outdir / "host_risk.png")

    print("OK ✅ Charts generated in reports/figures")
    print("- top_ports.png")
    print("- top_services.png")
    print("- host_risk.png")

if __name__ == "__main__":
    main()
