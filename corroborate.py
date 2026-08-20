from datetime import datetime, timezone

VALID_SOURCE_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def parse_iso_datetime(ts_str):
    if not isinstance(ts_str, str):
        return None
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def evaluate_corroboration(data) -> dict:
    # ========================================================
    # Rule 1: INVALID
    # ========================================================
    if not isinstance(data, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        }

    claim = data.get("claim")
    if not isinstance(claim, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        }

    claim_value = claim.get("value")
    if not isinstance(claim_value, str):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        }

    as_of_str = data.get("asOf")
    as_of_dt = parse_iso_datetime(as_of_str)
    if as_of_dt is None:
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        }

    staleness_days = data.get("stalenessDays")
    if (
        not isinstance(staleness_days, (int, float))
        or isinstance(staleness_days, bool)
        or staleness_days < 0
    ):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        }

    raw_sources = data.get("sources")
    if not isinstance(raw_sources, list):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        }

    # ========================================================
    # Filter & Parse Valid Sources
    # ========================================================
    staleness_seconds = float(staleness_days) * 86400.0
    valid_sources = []

    for s in raw_sources:
        if not isinstance(s, dict):
            continue

        s_id = s.get("id")
        s_origin = s.get("origin")
        s_value = s.get("value")
        s_observed_at_str = s.get("observedAt")
        s_type = s.get("type")

        if not (
            isinstance(s_id, str)
            and isinstance(s_origin, str)
            and isinstance(s_value, str)
            and isinstance(s_observed_at_str, str)
        ):
            continue

        if s_type not in VALID_SOURCE_TYPES:
            continue

        s_observed_dt = parse_iso_datetime(s_observed_at_str)
        if s_observed_dt is None:
            continue

        diff_seconds = (as_of_dt - s_observed_dt).total_seconds()
        is_fresh = diff_seconds <= staleness_seconds

        valid_sources.append({
            "id": s_id,
            "origin": s_origin,
            "value": s_value,
            "type": s_type,
            "authoritative": bool(s.get("authoritative") is True),
            "is_fresh": is_fresh,
        })

    # ========================================================
    # Rule 2: CONTRADICTED
    # ========================================================
    contradicting = [
        s for s in valid_sources
        if s["is_fresh"] and s["authoritative"] and s["value"] != claim_value
    ]

    if contradicting:
        contradicting_ids = sorted(list(set(s["id"] for s in contradicting)))
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": contradicting_ids,
        }

    # ========================================================
    # Rule 3: SUPPORTED
    # ========================================================
    agreeing_fresh = [
        s for s in valid_sources
        if s["is_fresh"] and s["value"] == claim_value
    ]

    by_origin = {}
    for s in agreeing_fresh:
        by_origin.setdefault(s["origin"], []).append(s)

    representatives = []
    for origin, src_list in by_origin.items():
        # Representative is the source with the lexicographically smallest id
        rep = min(src_list, key=lambda s: s["id"])
        representatives.append(rep)

    if len(representatives) >= 2:
        distinct_types = set(r["type"] for r in representatives)
        confidence = "high" if len(distinct_types) >= 2 else "medium"
        corroborating_ids = sorted([r["id"] for r in representatives])
        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": corroborating_ids,
        }

    # ========================================================
    # Rule 4: UNVERIFIED
    # ========================================================
    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }
