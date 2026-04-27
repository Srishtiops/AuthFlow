import os
import time
from collections import Counter

SUSPICIOUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".js",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
}
TRUST_ACTION_LOCK_THRESHOLD = 35


def format_timeline_entry(message, now=None):
    now = now or time.time()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    return f"[{timestamp}] {message}"


def append_timeline_event(session_data, message, now=None):
    entry = format_timeline_entry(message, now=now)
    session_data.setdefault("timeline", []).append(entry)
    session_data["timeline"] = session_data["timeline"][-20:]
    return entry


def create_session_profile(username, ip_address, user_agent="", accept_language=""):
    now = time.time()
    return {
        "username": username,
        "trusted_ip": ip_address,
        "current_ip": ip_address,
        "known_ips": {ip_address},
        "ip_change_count": 0,
        "request_timestamps": [now],
        "request_paths": [],
        "request_methods": [],
        "request_intervals": [],
        "sequence_window": [],
        "file_events": [],
        "risk_thresholds": {"view_only": 35, "blocked": 75},
        "risk_history": [0],
        "timeline": [format_timeline_entry(f"Login successful from {ip_address}", now=now)],
        "access_level": "full_access",
        "last_risk": 0,
    }


def trim_old_activity(session_data, now=None):
    now = now or time.time()
    session_data["request_timestamps"] = [
        stamp for stamp in session_data.get("request_timestamps", []) if now - stamp <= 60
    ]
    session_data["request_paths"] = session_data.get("request_paths", [])[-120:]
    session_data["request_methods"] = session_data.get("request_methods", [])[-120:]
    session_data["request_intervals"] = session_data.get("request_intervals", [])[-120:]
    session_data["sequence_window"] = session_data.get("sequence_window", [])[-30:]
    session_data["file_events"] = [
        event for event in session_data.get("file_events", []) if now - event["time"] <= 300
    ]


def record_request(
    session_data,
    current_ip,
    path,
    method="GET",
    user_agent="",
    accept_language="",
    now=None,
):
    now = now or time.time()
    trim_old_activity(session_data, now)

    previous_ip = session_data.get("current_ip")
    session_data["current_ip"] = current_ip
    previous_request_ts = session_data["request_timestamps"][-1] if session_data["request_timestamps"] else None
    session_data["request_timestamps"].append(now)
    if previous_request_ts:
        session_data["request_intervals"].append(now - previous_request_ts)
    session_data["request_paths"].append(path)
    session_data["request_methods"].append(method)
    session_data["sequence_window"].append(f"{method}:{path}")

    if previous_ip and previous_ip != current_ip:
        session_data["ip_change_count"] += 1
        session_data["known_ips"].add(current_ip)
        append_timeline_event(session_data, f"IP changed from {previous_ip} to {current_ip}", now=now)

    append_timeline_event(session_data, f"{method} {path}", now=now)


def inspect_file(filename):
    extension = os.path.splitext(filename.lower())[1]
    suspicious = extension in SUSPICIOUS_EXTENSIONS
    reason = f"Suspicious file type detected ({extension})" if suspicious else ""
    return suspicious, reason


def record_file_event(session_data, action, filename, allowed, reason="", suspicious=False, now=None):
    now = now or time.time()
    trim_old_activity(session_data, now)

    session_data["file_events"].append(
        {
            "time": now,
            "action": action,
            "filename": filename,
            "allowed": allowed,
            "reason": reason,
            "suspicious": suspicious,
        }
    )

    status = "allowed" if allowed else "blocked"
    details = f"{action.title()} {status}: {filename}"
    if reason:
        details = f"{details} ({reason})"
    append_timeline_event(session_data, details, now=now)


def calculate_behavior_risk(session_data, current_ip, now=None):
    now = now or time.time()
    trim_old_activity(session_data, now)

    risk = 0
    reasons = []
    request_timestamps = session_data.get("request_timestamps", [])
    recent_10s_requests = [stamp for stamp in request_timestamps if now - stamp <= 10]
    recent_60s_requests = list(request_timestamps)
    request_paths = session_data.get("request_paths", [])
    request_methods = session_data.get("request_methods", [])
    request_intervals = session_data.get("request_intervals", [])
    sequence_window = session_data.get("sequence_window", [])
    unique_paths_60s = len(set(request_paths[-len(recent_60s_requests) :])) if recent_60s_requests else 0
    unique_methods_60s = len(set(request_methods[-len(recent_60s_requests) :])) if recent_60s_requests else 0
    fast_intervals = [gap for gap in request_intervals[-40:] if gap < 0.35]
    file_events = session_data.get("file_events", [])
    recent_file_events = [event for event in file_events if now - event["time"] <= 60]
    recent_uploads = [
        event for event in recent_file_events if event["action"] in {"upload", "update", "delete"}
    ]
    suspicious_uploads = [event for event in recent_uploads if event["suspicious"]]
    blocked_actions = [event for event in recent_file_events if not event["allowed"]]

    # Refresh/bot-like pressure detection.
    if len(recent_10s_requests) >= 8:
        risk += 35
        reasons.append("Very high request burst detected in 10 seconds")
    elif len(recent_10s_requests) >= 5:
        risk += 20
        reasons.append("High request burst detected in 10 seconds")
    elif len(recent_60s_requests) >= 20:
        risk += 20
        reasons.append("High request volume detected in 60 seconds")

    if len(fast_intervals) >= 6:
        risk += 18
        reasons.append("Rapid bot-like click cadence detected")

    if unique_paths_60s >= 12:
        risk += 10
        reasons.append("Abnormal endpoint hopping pattern detected")

    if unique_methods_60s >= 3:
        risk += 6
        reasons.append("Unusual mix of request methods detected")

    if len(sequence_window) >= 8:
        repeated_sequences = Counter(zip(sequence_window, sequence_window[1:]))
        if repeated_sequences and repeated_sequences.most_common(1)[0][1] >= 5:
            risk += 18
            reasons.append("Sequence-based anomaly detected from repeated request loops")

    if recent_60s_requests:
        path_slice = request_paths[-len(recent_60s_requests) :]
        if path_slice:
            repeated_count = Counter(path_slice).most_common(1)[0][1]
            if repeated_count >= 10:
                risk += 14
                reasons.append("Excessive repeated page refresh pattern detected")

            dashboard_refreshes = sum(
                1
                for path in path_slice
                if path in {"/dashboard", "/api/user/dashboard"}
            )
            if dashboard_refreshes >= 12:
                risk += 34
                reasons.append("Continuous dashboard refresh storm detected")
            elif dashboard_refreshes >= 7:
                risk += 18
                reasons.append("High dashboard refresh pressure detected")

    if len(recent_uploads) >= 5:
        risk += 25
        reasons.append("Possible file spamming detected")

    if suspicious_uploads:
        risk += min(40, 20 * len(suspicious_uploads))
        reasons.append("Suspicious file type activity detected")

    if blocked_actions:
        risk += min(20, 5 * len(blocked_actions))
        reasons.append("Restricted actions were attempted")

    action_counter = Counter(event["action"] for event in recent_file_events)
    if action_counter.get("view", 0) >= 20:
        risk += 10
        reasons.append("Unusually high file access activity detected")

    # Adaptive scoring: tighten or relax thresholds based on persistent pressure.
    history = session_data.get("risk_history", [])
    moving_avg = (sum(history[-5:]) / min(5, len(history))) if history else 0
    thresholds = session_data.get("risk_thresholds", {"view_only": 45, "blocked": 90})
    if moving_avg >= 50:
        thresholds["view_only"] = 40
        thresholds["blocked"] = 85
    elif moving_avg <= 20:
        thresholds["view_only"] = 50
        thresholds["blocked"] = 92
    else:
        thresholds["view_only"] = 45
        thresholds["blocked"] = 90
    session_data["risk_thresholds"] = thresholds

    risk = min(risk, 100)
    access_level = access_from_risk(risk, thresholds)

    session_data["last_risk"] = risk
    session_data["access_level"] = access_level
    session_data["risk_history"].append(risk)
    session_data["risk_history"] = session_data["risk_history"][-12:]

    return {
        "risk": risk,
        "trust_score": 100 - risk,
        "reasons": reasons or ["No active threats detected"],
        "access_level": access_level,
        "requests_last_10s": len(recent_10s_requests),
        "requests_last_60s": len(recent_60s_requests),
        "uploads_last_60s": len(recent_uploads),
        "suspicious_uploads_last_60s": len(suspicious_uploads),
        "fast_click_intervals": len(fast_intervals),
        "unique_paths_60s": unique_paths_60s,
        "sequence_alerts": 1 if any("Sequence-based anomaly" in r for r in reasons) else 0,
        "dashboard_refreshes_60s": (
            sum(
                1
                for path in request_paths[-len(recent_60s_requests) :]
                if path in {"/dashboard", "/api/user/dashboard"}
            )
            if recent_60s_requests
            else 0
        ),
    }


def detect_request_flood(session_data, now=None):
    now = now or time.time()
    trim_old_activity(session_data, now)

    request_timestamps = session_data.get("request_timestamps", [])
    request_intervals = session_data.get("request_intervals", [])
    request_paths = session_data.get("request_paths", [])
    request_methods = session_data.get("request_methods", [])
    recent_10s_requests = [stamp for stamp in request_timestamps if now - stamp <= 10]
    recent_60s_requests = list(request_timestamps)
    fast_intervals = [gap for gap in request_intervals[-80:] if gap < 0.25]
    path_slice = request_paths[-len(recent_60s_requests) :] if recent_60s_requests else []
    method_slice = request_methods[-len(recent_60s_requests) :] if recent_60s_requests else []

    severity = "none"
    reasons = []
    if len(recent_10s_requests) >= 20 or len(recent_60s_requests) >= 80:
        severity = "critical"
        reasons.append("Extreme request burst in a short time window")
    elif len(recent_10s_requests) >= 12 or len(recent_60s_requests) >= 45:
        severity = "warning"
        reasons.append("Sustained high request rate")

    if len(fast_intervals) >= 20:
        severity = "critical"
        reasons.append("Automated rapid-fire request cadence")
    elif len(fast_intervals) >= 10 and severity == "none":
        severity = "warning"
        reasons.append("Very fast request cadence")

    if path_slice:
        top_path, top_count = Counter(path_slice).most_common(1)[0]
        if top_count >= 24:
            severity = "critical"
            reasons.append(f"Unusually high repeated refreshes on {top_path}")
        elif top_count >= 12:
            if severity == "none":
                severity = "warning"
            reasons.append(f"Repeated heavy refreshes on {top_path}")

    if method_slice:
        method_counter = Counter(method_slice)
        post_count = method_counter.get("POST", 0)
        if post_count >= 16:
            severity = "critical"
            reasons.append("Unusually high volume of write/action requests")
        elif post_count >= 8:
            if severity == "none":
                severity = "warning"
            reasons.append("Repeated action submissions detected")

    return {
        "flagged": severity != "none",
        "severity": severity,
        "reasons": reasons,
        "requests_last_10s": len(recent_10s_requests),
        "requests_last_60s": len(recent_60s_requests),
        "fast_intervals": len(fast_intervals),
    }


def access_from_risk(risk, thresholds=None):
    thresholds = thresholds or {"view_only": 45, "blocked": 90}
    if risk >= thresholds["blocked"]:
        return "blocked"
    if risk >= thresholds["view_only"]:
        return "view_only"
    return "full_access"


def can_perform(access_level, action, trust_score=100):
    # Hard block: very low trust means no user activity is allowed.
    if trust_score <= TRUST_ACTION_LOCK_THRESHOLD:
        return False

    # Medium-low trust: allow read-only flow, block mutating operations.
    if trust_score <= 45 and action in {"upload", "create", "update", "delete"}:
        return False

    if access_level == "blocked":
        return action == "view" and trust_score > 15
    if access_level == "view_only":
        return action == "view"
    return True
