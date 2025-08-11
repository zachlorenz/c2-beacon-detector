from math import sqrt, log
from statistics import mean, pstdev

def _deltas(times):
    return [b - a for a, b in zip(times, times[1:]) if b >= a]

def _cv(values):
    if len(values) < 2:
        return 9e9
    m = mean(values)
    if m <= 0:
        return 9e9
    s = pstdev(values)  # population stdev
    return s / m

def _score_flow(delta_list, min_interval, max_interval):
    if len(delta_list) < 2:
        return 0.0
    m = mean(delta_list)
    cv = _cv(delta_list)

    # base: low CV = good (periodic)
    base = 1.0 / (cv + 0.01)

    # interval prior: penalize too small/large means
    if m < min_interval:
        base *= 0.5
    if m > max_interval:
        base *= 0.6

    return max(base, 0.0), m, cv

def score_flows(flows, min_pkts=6, min_interval=5.0, max_interval=3600.0, cv_threshold=0.20, top_n=10):
    results = []
    total = {"flows": 0, "considered": 0, "candidates": 0}

    total["flows"] = len(flows)

    for key, times in flows.items():
        if len(times) < min_pkts:
            continue

        deltas = _deltas(times)
        if not deltas:
            continue

        # small outlier guard: drop the single largest gap
        if len(deltas) >= 4:
            biggest = max(deltas)
            trimmed = [x for x in deltas if x != biggest]  # drops first biggest only
            if len(trimmed) >= 3:
                deltas = trimmed

        score, mean_interval, cv = _score_flow(deltas, min_interval, max_interval)

        total["considered"] += 1
        candidate = cv <= cv_threshold and (min_interval <= mean_interval <= max_interval)

        if candidate:
            total["candidates"] += 1

        src, sport, dst, dport, proto = key
        results.append({
            "src": src, "sport": sport, "dst": dst, "dport": dport, "proto": proto,
            "count": len(times),
            "mean_interval": round(mean_interval, 3),
            "cv": round(cv, 4),
            "score": round(score + (0.15 * log(len(times))), 4),  # slight bonus for longer runs
            "reason": f"cv={cv:.3f}, mean={mean_interval:.1f}s, count={len(times)}",
            "candidate": candidate
        })

    # rank by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_n], total
