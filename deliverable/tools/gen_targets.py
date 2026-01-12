import argparse
import ipaddress
import json
from pathlib import Path
from datetime import datetime

def parse_args():
    p = argparse.ArgumentParser(description="Generate target IP list(s) from CIDR(s).")
    p.add_argument("--cidr", action="append", required=True,
                   help="CIDR block, can be given multiple times. e.g. 192.168.1.0/24")
    p.add_argument("--exclude", action="append", default=[],
                   help="Exclude a single IP or CIDR. e.g. 192.168.1.1 or 192.168.1.0/28")
    p.add_argument("--batch-size", type=int, default=256, help="IPs per batch file")
    p.add_argument("--max-hosts", type=int, default=200000,
                   help="Safety limit to avoid generating huge lists by mistake")
    p.add_argument("--outdir", default="targets", help="Output directory")
    return p.parse_args()

def main():
    args = parse_args()
    outdir = Path(args.outdir)
    batches_dir = outdir / "batches"
    outdir.mkdir(parents=True, exist_ok=True)
    batches_dir.mkdir(parents=True, exist_ok=True)

    include_ips = set()
    include_nets = []
    for c in args.cidr:
        net = ipaddress.ip_network(c, strict=False)
        include_nets.append(str(net))
        for ip in net.hosts():
            include_ips.add(str(ip))

    exclude_ips = set()
    exclude_specs = []
    for e in args.exclude:
        exclude_specs.append(e)
        if "/" in e:
            enet = ipaddress.ip_network(e, strict=False)
            for ip in enet.hosts():
                exclude_ips.add(str(ip))
        else:
            exclude_ips.add(str(ipaddress.ip_address(e)))

    final_ips = sorted(set(include_ips) - set(exclude_ips), key=lambda x: ipaddress.ip_address(x))

    if len(final_ips) > args.max_hosts:
        raise SystemExit(
            f"[ABORT] Too many hosts generated: {len(final_ips)} > max_hosts={args.max_hosts}. "
            f"Use smaller CIDR(s) or increase --max-hosts carefully."
        )

    # Write all targets
    all_path = outdir / "all_targets.txt"
    all_path.write_text("\n".join(final_ips) + ("\n" if final_ips else ""), encoding="utf-8")

    # Write batches
    batch_files = []
    for i in range(0, len(final_ips), args.batch_size):
        batch = final_ips[i:i + args.batch_size]
        name = f"batch_{i//args.batch_size:04d}.txt"
        p = batches_dir / name
        p.write_text("\n".join(batch) + ("\n" if batch else ""), encoding="utf-8")
        batch_files.append(str(p))

    summary = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "include_cidrs": include_nets,
        "exclude": exclude_specs,
        "total_targets": len(final_ips),
        "batch_size": args.batch_size,
        "batch_count": len(batch_files),
        "all_targets_file": str(all_path),
        "batch_files_example": batch_files[:3],
    }

    meta_dir = Path("meta")
    meta_dir.mkdir(exist_ok=True)
    (meta_dir / "targets_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("OK ✅ Targets generated.")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
