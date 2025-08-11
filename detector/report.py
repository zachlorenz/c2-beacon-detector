import json
from datetime import datetime, timezone

def write_report(filename, pcap, params, results, totals):
    doc = {
        "file_analyzed": pcap,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "params": params,
        "totals": totals,
        "top_flows": results
    }
    with open(filename, "w") as f:
        json.dump(doc, f, indent=2)
    print(f"[+] Wrote {filename} with {len(results)} flows")
