#!/usr/bin/env python3
# run_detector.py
import argparse
from detector.main import run

def parse_args():
    p = argparse.ArgumentParser(
        description="Detect periodic C2 beacons in PCAPs using timing analysis."
    )
    p.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    p.add_argument("--proto", default="any", choices=["any", "tcp", "udp", "dns", "http"],
                   help="Limit analysis to a protocol family (basic filter)")
    p.add_argument("--filter", default=None,
                   help="Optional Wireshark display filter (overrides --proto if set)")
    p.add_argument("--prefilter", action="store_true",
                   help="Run tshark first to create a filtered temp pcap for speed")
    p.add_argument("--limit", type=int, default=None,
                   help="Optional packet limit for prefilter step (tshark -c N)")
    p.add_argument("--min-pkts", type=int, default=6, help="Minimum packets per flow")
    p.add_argument("--min-interval", type=float, default=5.0, help="Min mean interval (sec)")
    p.add_argument("--max-interval", type=float, default=3600.0, help="Max mean interval (sec)")
    p.add_argument("--cv-threshold", type=float, default=0.20, help="Max coefficient of variation")
    p.add_argument("--top", type=int, default=10, help="Top N flows to report")
    p.add_argument("--report", default="beacon_report.json", help="Output JSON report path")
    p.add_argument("--keep-prefilter", action="store_true",
                   help="Keep the filtered temp file (saved next to original)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run(args)
