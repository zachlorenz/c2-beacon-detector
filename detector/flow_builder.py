# detector/flow_builder.py
import pyshark

def _display_filter_for(proto: str) -> str | None:
    if proto == "dns":
        return "dns"
    if proto == "http":
        return "http"
    if proto == "tcp":
        return "tcp && tcp.len > 0"
    if proto == "udp":
        return "udp"
    return None

def build_flows(pcap_path: str, proto: str = "any"):
    dfilter = _display_filter_for(proto)
    common_kwargs = dict(
        keep_packets=False,
        use_json=True,
        include_raw=False,
        tshark_path=None,
        custom_parameters=['-n']  # disable name resolution
    )

    cap = (pyshark.FileCapture(pcap_path, display_filter=dfilter, **common_kwargs)
           if dfilter else
           pyshark.FileCapture(pcap_path, **common_kwargs))

    flows = {}
    for pkt in cap:
        try:
            ts = float(pkt.frame_info.time_epoch)
            src = pkt.ip.src
            dst = pkt.ip.dst
        except Exception:
            continue

        if hasattr(pkt, "tcp"):
            proto_name = "TCP"
            try:
                sport = int(pkt.tcp.srcport); dport = int(pkt.tcp.dstport)
            except Exception:
                continue
        elif hasattr(pkt, "udp"):
            proto_name = "UDP"
            try:
                sport = int(pkt.udp.srcport); dport = int(pkt.udp.dstport)
            except Exception:
                continue
        else:
            # keep it simple & fast: skip non-TCP/UDP
            continue

        key = (src, sport, dst, dport, proto_name)
        flows.setdefault(key, []).append(ts)

    cap.close()
    for k in flows:
        flows[k].sort()
    return flows
