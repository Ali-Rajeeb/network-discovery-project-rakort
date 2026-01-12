import argparse
import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

TIME_RE = re.compile(r"time[=<]\s*(\d+)\s*ms", re.IGNORECASE)

def ping_once(ip: str, timeout_ms: int) -> Tuple[bool, Optional[int], str]:
    """
    Windows ping:
      -n 1 : 1 paket
      -w X : timeout (ms)
    """
    try:
        start = time.time()
        p = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            text=True
        )
        elapsed_ms = int((time.time() - start) * 1000)

        out = (p.stdout or "") + "\n" + (p.stderr or "")
        ok = (p.returncode == 0)

        # Ping çıktısından "time=XXms" çekmeye çalış
        m = TIME_RE.search(out)
        rtt = int(m.group(1)) if m else (elapsed_ms if ok else None)

        return ok, rtt, "icmp"
    except Exception:
        return False, None, "icmp"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True, help="targets/all_targets.txt path")
    ap.add_argument("--out", default="dataset/alive_hosts.jsonl", help="output jsonl path")
    ap.add_argument("--timeout-ms", type=int, default=400, help="ping timeout in ms")
    ap.add_argument("--threads", type=int, default=60, help="parallel threads")
    args = ap.parse_args()

    targets_path = Path(args.targets)
    out_path = Path(args.out)

    # Çıktı klasörleri yoksa oluştur
    out_path.parent.mkdir(parents=True, exist_ok=True)
    Path("meta").mkdir(exist_ok=True)

    # targets dosyasından IP'leri oku
    ips = [line.strip() for line in targets_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    t0 = time.time()
    alive_count = 0

    # Sonuçları JSONL olarak yaz (her satır 1 JSON)
    with out_path.open("w", encoding="utf-8") as f:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(ping_once, ip, args.timeout_ms): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                ok, rtt, method = fut.result()
                if ok:
                    alive_count += 1

                rec = {
                    "ip": ip,
                    "alive": ok,
                    "rtt_ms": rtt,
                    "method": method,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    total_ms = int((time.time() - t0) * 1000)

    summary = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "targets_file": str(targets_path),
        "out_file": str(out_path),
        "total_targets": len(ips),
        "alive_count": alive_count,
        "dead_count": len(ips) - alive_count,
        "timeout_ms": args.timeout_ms,
        "threads": args.threads,
        "duration_ms": total_ms
    }

    Path("meta/alive_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("OK ✅ Alive scan finished.")
    print(json.dumps(summary, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
