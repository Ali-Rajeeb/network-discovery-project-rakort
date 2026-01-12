import argparse
import json
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", default="raw/nmap_top.xml", help="Input Nmap XML file")
    ap.add_argument("--out", default="dataset/services.jsonl", help="Output JSONL file")
    args = ap.parse_args()

    xml_path = Path(args.xml)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    scan_ts = datetime.utcnow().isoformat() + "Z"

    count = 0
    with out_path.open("w", encoding="utf-8") as f:
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            addr = host.find("address[@addrtype='ipv4']")
            ip = addr.get("addr") if addr is not None else None
            if not ip:
                continue

            hn = host.find("hostnames/hostname")
            hostname = hn.get("name") if hn is not None else None

            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                proto = port.get("protocol")
                portid = port.get("portid")

                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else None

                # sadece open portları yaz
                if state != "open":
                    continue

                svc = port.find("service")
                service_name = svc.get("name") if svc is not None else None
                product = svc.get("product") if svc is not None else None
                version = svc.get("version") if svc is not None else None
                extrainfo = svc.get("extrainfo") if svc is not None else None
                tunnel = svc.get("tunnel") if svc is not None else None  # ssl gibi

                cpes = []
                if svc is not None:
                    for cpe in svc.findall("cpe"):
                        if cpe.text:
                            cpes.append(cpe.text.strip())

                rec = {
                    "ip": ip,
                    "hostname": hostname,
                    "proto": proto,
                    "port": int(portid),
                    "state": state,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "tunnel": tunnel,
                    "cpes": cpes,
                    "scan_timestamp": scan_ts
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                count += 1

    print("OK ✅ Parsed Nmap XML.")
    print(f"Wrote {count} open-port service records to: {out_path}")

if __name__ == "__main__":
    main()
