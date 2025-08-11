# detector/prefilter.py
import os
import subprocess
import tempfile
from shutil import which

PROTO_FILTERS = {
    "dns":  "dns",
    "http": "http",
    "tcp":  "tcp && tcp.len > 0",  # skip pure ACKs
    "udp":  "udp",
    "any":  None
}

def resolve_filter(proto: str, custom_filter: str | None) -> str | None:
    if custom_filter:
        return custom_filter
    return PROTO_FILTERS.get(proto, None)

def prefilter_pcap(input_path: str,
                   proto: str = "any",
                   custom_filter: str | None = None,
                   limit: int | None = None,
                   keep_file: bool = False) -> str:
    """
    Runs tshark to write a filtered pcapng and returns its path.
    """
    if which("tshark") is None:
        raise RuntimeError("tshark not found. Install with: sudo apt install tshark -y")

    disp = resolve_filter(proto, custom_filter)
    # Build output path
    if keep_file:
        base, _ = os.path.splitext(input_path)
        out_path = f"{base}.prefiltered.pcapng"
    else:
        tmp = tempfile.NamedTemporaryFile(prefix="prefilter_", suffix=".pcapng", delete=False)
        out_path = tmp.name
        tmp.close()

    cmd = ["tshark", "-r", input_path, "-n", "-w", out_path]
    if disp:
        cmd.extend(["-Y", disp])
    if limit:
        cmd.extend(["-c", str(limit)])

    # Run tshark
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"tshark failed: {res.stderr.strip()}")

    return out_path
