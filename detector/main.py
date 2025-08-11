# detector/main.py
import os
from detector.flow_builder import build_flows
from detector.timing_metrics import score_flows
from detector.report import write_report
from detector.prefilter import prefilter_pcap

def run(args):
    pcap_to_use = args.pcap

    # Auto-prefilter if --prefilter set OR a filter is provided
    if args.prefilter or args.filter is not None or args.proto != "any":
        print("[+] Prefiltering with tshark for speed...")
        pcap_to_use = prefilter_pcap(
            input_path=args.pcap,
            proto=args.proto,
            custom_filter=args.filter,
            limit=args.limit,
            keep_file=args.keep_prefilter
        )
        print(f"[+] Using filtered PCAP: {pcap_to_use}")

    print(f"[+] Loading {pcap_to_use}")
    # When we've already filtered, pass proto='any' to avoid re-filtering in pyshark
    flows = build_flows(pcap_to_use, proto="any" if pcap_to_use != args.pcap else args.proto)
    print(f"[+] Built {len(flows)} flows (pre-filter)")

    ranked, stats = score_flows(
        flows,
        min_pkts=args.min_pkts,
        min_interval=args.min_interval,
        max_interval=args.max_interval,
        cv_threshold=args.cv_threshold,
        top_n=args.top
    )

    write_report(
        filename=args.report,
        pcap=args.pcap,
        params={
            "prefilter": bool(pcap_to_use != args.pcap),
            "filtered_file": pcap_to_use if pcap_to_use != args.pcap else None,
            "proto": args.proto,
            "filter": args.filter,
            "limit": args.limit,
            "min_pkts": args.min_pkts,
            "min_interval": args.min_interval,
            "max_interval": args.max_interval,
            "cv_threshold": args.cv_threshold,
            "top": args.top
        },
        results=ranked,
        totals=stats
    )

    # Cleanup temp file if we didn't ask to keep it
    if (pcap_to_use != args.pcap) and (not args.keep_prefilter):
        try:
            os.remove(pcap_to_use)
            print(f"[+] Removed temp file: {pcap_to_use}")
        except Exception:
            pass

    print(f"[+] Done. Report: {args.report}")
