from datetime import datetime
from pathlib import Path
import socket

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from database import (
    SHARED_DIR,
    add_admin_alert,
    append_user_activity,
    close_user_access,
    create_user,
    dismiss_admin_alert,
    get_admin_alerts,
    get_all_sessions,
    get_all_users,
    get_file_owner,
    get_session,
    get_user,
    list_shared_files,
    open_user_access,
    remove_file_owner,
    save_session,
    set_file_owner,
    set_user_monitoring,
    update_user_hours,
    update_user_security_snapshot,
)
from monitor import (
    SUSPICIOUS_EXTENSIONS,
    TRUST_ACTION_LOCK_THRESHOLD,
    can_perform,
    calculate_behavior_risk,
    create_session_profile,
    detect_request_flood,
    inspect_file,
    record_file_event,
    record_request,
)

app = Flask(__name__)
app.secret_key = "secret123"
MAX_UPLOAD_SIZE = 10 * 1024 * 1024
ATTACK_ALERT_COOLDOWN_SECONDS = 45
ANON_TRAFFIC_PROFILES = {}
LAST_ATTACK_ALERT_AT = {}
IP_TO_RECENT_USER = {}
REFRESH_ALERT_COOLDOWN_SECONDS = 25
LAST_REFRESH_ALERT_AT = {}
COMPANY_LOGIN_START = "08:00"
COMPANY_LOGIN_END = "17:00"


def detect_local_ipv4():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        ip_address = probe.getsockname()[0]
        if ip_address and not ip_address.startswith("127."):
            return ip_address
    except OSError:
        pass
    finally:
        probe.close()

    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
        if hostname_ip and not hostname_ip.startswith("127."):
            return hostname_ip
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            candidate = info[4][0]
            if candidate and not candidate.startswith("127."):
                return candidate
    except OSError:
        pass

    return "127.0.0.1"


def print_startup_access_urls(host, port):
    local_ip = detect_local_ipv4()
    print(f"[startup] Flask server binding on {host}:{port}")
    print(f"[startup] Network URL: http://{local_ip}:{port}")


def current_username():
    return session.get("user")


def current_role():
    return session.get("role")


def current_session_data():
    username = current_username()
    if not username:
        return None
    return get_session(username)


def parse_time_value(value):
    cleaned = str(value or "").strip()
    if not cleaned:
        raise ValueError("Time value is required")

    formats = ("%H:%M", "%I:%M %p", "%I:%M%p")
    upper_cleaned = cleaned.upper()
    for fmt in formats:
        try:
            return datetime.strptime(upper_cleaned, fmt)
        except ValueError:
            continue
    raise ValueError("Invalid time format")


def normalize_time_value(value):
    return parse_time_value(value).strftime("%H:%M")


def format_time_ampm(value):
    return parse_time_value(value).strftime("%I:%M %p").lstrip("0")


def is_ajax_request():
    return request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest"


def admin_response(message, message_type="success", status=200, selected_user=""):
    if is_ajax_request():
        return jsonify(
            {
                "ok": message_type != "error",
                "message": message,
                "message_type": message_type,
                "selected_user": selected_user,
            }
        ), status

    kwargs = {"message": message, "message_type": message_type}
    if selected_user:
        kwargs["user"] = selected_user
    return redirect(url_for("admin_dashboard", **kwargs))


def api_error(message, status=400, code="error", **extra):
    payload = {"ok": False, "message": message, "code": code}
    payload.update(extra)
    return jsonify(payload), status


def api_success(message="", **extra):
    payload = {"ok": True, "message": message}
    payload.update(extra)
    return jsonify(payload)


def log_user_activity(username, message):
    if username:
        append_user_activity(username, message)


def manual_access_is_open(user, current_time=None):
    if not user or user.get("role") != "user":
        return False
    current_time = current_time or datetime.now()
    access_start = user.get("manual_access_start")
    access_end = user.get("manual_access_end")
    if not access_start or not access_end:
        return False
    try:
        start = parse_time_value(access_start)
        end = parse_time_value(access_end)
    except ValueError:
        return False

    start_minutes = start.hour * 60 + start.minute
    end_minutes = end.hour * 60 + end.minute
    current_minutes = current_time.hour * 60 + current_time.minute

    if start_minutes == end_minutes:
        return False
    if start_minutes < end_minutes:
        return start_minutes <= current_minutes <= end_minutes
    return current_minutes >= start_minutes or current_minutes <= end_minutes


def manual_access_label(user):
    if not user:
        return ""
    access_start = user.get("manual_access_start")
    access_end = user.get("manual_access_end")
    if not access_start or not access_end:
        return ""
    return f"{format_time_ampm(access_start)} - {format_time_ampm(access_end)}"


def format_schedule_window(user):
    if not user or user.get("role") != "user":
        return "Not configured"

    start = parse_time_value(user["login_start"])
    end = parse_time_value(user["login_end"])
    return f"{start.strftime('%I:%M %p').lstrip('0')} - {end.strftime('%I:%M %p').lstrip('0')}"


def is_within_login_hours(user, current_time=None):
    if not user or user.get("role") != "user":
        return True

    current_time = current_time or datetime.now()
    if manual_access_is_open(user, current_time):
        return True

    start = parse_time_value(user["login_start"])
    end = parse_time_value(user["login_end"])

    start_minutes = start.hour * 60 + start.minute
    end_minutes = (end.hour * 60 + end.minute) % (24 * 60)
    current_minutes = current_time.hour * 60 + current_time.minute

    if start_minutes == end_minutes:
        return True
    if start_minutes < end_minutes:
        return start_minutes <= current_minutes <= end_minutes
    return current_minutes >= start_minutes or current_minutes <= end_minutes


def enforce_user_login_hours():
    username = current_username()
    if not username or current_role() != "user":
        return None

    user = get_user(username)
    if is_within_login_hours(user):
        return None

    session.clear()
    return redirect(
        url_for(
            "login",
            error="Your login hours have ended. Please contact the admin to open access for you.",
        )
    )


def require_active_user_session():
    session_data = current_session_data()
    if not session_data or current_role() != "user":
        return None, redirect(url_for("login"))

    login_window_redirect = enforce_user_login_hours()
    if login_window_redirect:
        return None, login_window_redirect

    return session_data, None


def validate_login_hours(login_start, login_end):
    try:
        parse_time_value(login_start)
        parse_time_value(login_end)
    except ValueError:
        return False
    return True


def upload_size(file_storage):
    file_storage.stream.seek(0, 2)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    return size


def is_monitoring_enabled(username):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return True
    return bool(user.get("monitoring_enabled", True))


def frozen_security_state(session_data, username):
    user = get_user(username) or {}
    frozen_risk = int(user.get("last_risk_score", session_data.get("last_risk", 0)))
    frozen_trust = int(user.get("last_trust_score", max(0, 100 - frozen_risk)))
    frozen_access = str(user.get("last_access_level", session_data.get("access_level", "full_access")))
    request_timestamps = session_data.get("request_timestamps", [])
    now = now_seconds()
    recent_10s = [stamp for stamp in request_timestamps if now - stamp <= 10]
    recent_60s = [stamp for stamp in request_timestamps if now - stamp <= 60]
    risk_history = session_data.get("risk_history", [])
    labels = list(range(1, len(risk_history) + 1))
    return {
        "risk": frozen_risk,
        "trust_score": frozen_trust,
        "reasons": ["Monitoring is paused by admin. Trust score is frozen."],
        "access_level": frozen_access,
        "requests_last_10s": len(recent_10s),
        "requests_last_60s": len(recent_60s),
        "uploads_last_60s": 0,
        "suspicious_uploads_last_60s": 0,
        "fast_click_intervals": 0,
        "unique_paths_60s": 0,
        "sequence_alerts": 0,
        "risk_data": risk_history,
        "labels": labels,
    }


def build_dashboard_state(session_data, current_ip, selected_file=None):
    username = session_data.get("username")
    monitoring_enabled = is_monitoring_enabled(username)
    if monitoring_enabled:
        result = calculate_behavior_risk(session_data, current_ip)
        if username:
            update_user_security_snapshot(
                username=username,
                risk=result["risk"],
                trust_score=result["trust_score"],
                access_level=result["access_level"],
            )
    else:
        result = frozen_security_state(session_data, username)

    files = [file_info for file_info in list_shared_files() if file_info.get("owner") == username]
    preview_file = None
    if selected_file and can_perform(result["access_level"], "view", result["trust_score"]):
        for file_info in files:
            if file_info["name"] == selected_file:
                preview_file = load_preview(selected_file)
                break

    labels = list(range(1, len(session_data["risk_history"]) + 1))
    previous_risk = session_data["risk_history"][-2] if len(session_data["risk_history"]) > 1 else result["risk"]
    risk_delta = (result["risk"] - previous_risk) if monitoring_enabled else 0
    return {
        "risk": result["risk"],
        "trust_score": result["trust_score"],
        "reasons": result["reasons"],
        "access_level": result["access_level"],
        "requests_last_10s": result["requests_last_10s"],
        "requests_last_60s": result["requests_last_60s"],
        "uploads_last_60s": result["uploads_last_60s"],
        "suspicious_uploads_last_60s": result["suspicious_uploads_last_60s"],
        "fast_click_intervals": result["fast_click_intervals"],
        "unique_paths_60s": result["unique_paths_60s"],
        "sequence_alerts": result["sequence_alerts"],
        "risk_delta": risk_delta,
        "risk_data": session_data["risk_history"],
        "labels": labels,
        "files": files,
        "preview_file": preview_file,
    }


def build_admin_sessions(selected_username=None):
    sessions = []
    for username, session_data in get_all_sessions().items():
        if selected_username and username != selected_username:
            continue
        user = get_user(username)
        current_ip = session_data.get("current_ip") or session_data.get("trusted_ip") or "unknown"
        # Admin should see the latest persisted user trust snapshot, not a separate
        # recalculation path that can diverge from what the user just saw.
        state = frozen_security_state(session_data, username)
        sessions.append(
            {
                "username": username,
                "current_ip": current_ip,
                "trusted_ip": session_data.get("trusted_ip", "unknown"),
                "risk": state["risk"],
                "trust_score": state["trust_score"],
                "reasons": state["reasons"],
                "access_level": state["access_level"],
                "access_label": access_label(state["access_level"]),
                "requests_last_10s": state["requests_last_10s"],
                "requests_last_60s": state["requests_last_60s"],
                "uploads_last_60s": state["uploads_last_60s"],
                "suspicious_uploads_last_60s": state["suspicious_uploads_last_60s"],
                "fast_click_intervals": state["fast_click_intervals"],
                "unique_paths_60s": state["unique_paths_60s"],
                "sequence_alerts": state["sequence_alerts"],
                "timeline": session_data["timeline"][-10:],
                "full_timeline": list(reversed(session_data["timeline"])),
                "risk_data": state["risk_data"],
                "manual_access_open": manual_access_is_open(user) if user else False,
                "manual_access_until": manual_access_label(user) if user else "",
                "monitoring_enabled": bool(user.get("monitoring_enabled", True)) if user else True,
            }
        )
    return sorted(sessions, key=lambda item: item["username"].lower())


def build_admin_users(selected_username=None):
    users = []
    for username, user in get_all_users().items():
        if user.get("role") != "user":
            continue

        users.append(
            {
                "username": username,
                "login_window": format_schedule_window(user),
                "within_hours": is_within_login_hours(user),
                "manual_access_open": manual_access_is_open(user),
                "manual_access_until": manual_access_label(user),
                "monitoring_enabled": user.get("monitoring_enabled", True),
                "is_action_locked": int(user.get("last_trust_score", 100)) <= TRUST_ACTION_LOCK_THRESHOLD,
                "selected": username == selected_username,
            }
        )
    return sorted(users, key=lambda item: item["username"].lower())


def build_admin_user_logs(selected_username=None):
    logs = []
    for username, session_data in get_all_sessions().items():
        if selected_username and username != selected_username:
            continue

        for entry in reversed(session_data.get("timeline", [])):
            logs.append({"username": username, "entry": entry})
    return logs


def build_admin_user_profile(selected_username, sessions):
    if not selected_username:
        return None

    user = get_user(selected_username)
    if not user or user.get("role") != "user":
        return None

    session_data = get_session(selected_username)
    session_summary = next((item for item in sessions if item["username"] == selected_username), None)

    trust_score = int(user.get("last_trust_score", 100))
    access_state = "No active session"

    if session_summary:
        trust_score = session_summary["trust_score"]
        access_state = session_summary["access_label"]
    elif session_data:
        trust_score = int(user.get("last_trust_score", 100 - int(session_data.get("last_risk", 0))))
        access_state = access_label(session_data.get("access_level", "full_access"))

    session_timeline = list(reversed(session_data.get("timeline", []))) if session_data else []
    historical_logs = list(reversed(user.get("activity_logs", [])))
    file_activity = []
    if session_data:
        for event in reversed(session_data.get("file_events", [])):
            if (
                event.get("action") == "view"
                and not event.get("allowed")
                and "current access level" in event.get("reason", "").lower()
            ):
                continue
            file_activity.append(
                {
                    "time": datetime.fromtimestamp(event["time"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "action": event.get("action", "unknown"),
                    "action_label": event.get("action", "unknown").title(),
                    "filename": event.get("filename", "unknown"),
                    "status": "Allowed" if event.get("allowed") else "Blocked",
                    "reason": event.get("reason", ""),
                }
            )
            if len(file_activity) >= 12:
                break

    latest_upload = next((item for item in file_activity if item["action"] == "upload"), None)
    access_start_default = format_time_ampm(user.get("manual_access_start") or user.get("login_start", COMPANY_LOGIN_START))
    access_end_default = format_time_ampm(user.get("manual_access_end") or user.get("login_end", COMPANY_LOGIN_END))

    return {
        "username": selected_username,
        "login_window": format_schedule_window(user),
        "within_hours": is_within_login_hours(user),
        "manual_access_open": manual_access_is_open(user),
        "manual_access_until": manual_access_label(user),
        "monitoring_enabled": user.get("monitoring_enabled", True),
        "has_active_session": session_data is not None,
        "trust_score": trust_score,
        "is_action_locked": int(trust_score) <= TRUST_ACTION_LOCK_THRESHOLD,
        "access_state": access_state,
        "latest_upload": latest_upload,
        "access_start_default": access_start_default,
        "access_end_default": access_end_default,
        "file_activity": file_activity,
        "logs": historical_logs if historical_logs else session_timeline,
    }


def load_preview(filename):
    path = safe_shared_path(filename)
    if not path or not path.exists():
        return None

    extension = path.suffix.lower()
    preview_type = "download"
    content = ""

    if extension == ".pdf":
        preview_type = "pdf"
    elif extension in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        preview_type = "image"
    elif extension in {".txt", ".md", ".csv", ".json"} or not extension:
        preview_type = "text"
        try:
            content = path.read_text(encoding="utf-8")[:2000]
        except UnicodeDecodeError:
            preview_type = "download"
            content = "This file cannot be shown as text, but it can be opened in the browser."
    else:
        try:
            content = path.read_text(encoding="utf-8")[:2000]
            preview_type = "text"
        except UnicodeDecodeError:
            content = "This file type does not support inline preview. Open it in a new tab to review it."

    can_open_inline = True
    try:
        updated = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        updated = ""

    return {
        "name": path.name,
        "content": content,
        "preview_type": preview_type,
        "can_open_inline": can_open_inline,
        "updated": updated,
    }


def safe_shared_path(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        return None
    return SHARED_DIR / safe_name


def user_can_access_file(username, filename):
    if not username:
        return False
    return get_file_owner(filename) == username


def access_label(access_level):
    labels = {
        "full_access": "Secure",
        "view_only": "Review Only",
        "blocked": "Restricted",
    }
    return labels.get(access_level, access_level)


def dashboard_route_for_role(role):
    return "admin_dashboard" if role == "admin" else "dashboard"


def now_seconds():
    return datetime.now().timestamp()


def attack_signal_key(actor_label, ip_address):
    return f"{actor_label}@{ip_address}"


def should_emit_attack_alert(signal_key, now=None):
    now = now or now_seconds()
    previous = LAST_ATTACK_ALERT_AT.get(signal_key, 0)
    if now - previous < ATTACK_ALERT_COOLDOWN_SECONDS:
        return False
    LAST_ATTACK_ALERT_AT[signal_key] = now
    return True


def should_emit_refresh_alert(signal_key, now=None):
    now = now or now_seconds()
    previous = LAST_REFRESH_ALERT_AT.get(signal_key, 0)
    if now - previous < REFRESH_ALERT_COOLDOWN_SECONDS:
        return False
    LAST_REFRESH_ALERT_AT[signal_key] = now
    return True


def detect_dashboard_refresh_pressure(session_data, now=None):
    now = now or now_seconds()
    timestamps = session_data.get("request_timestamps", [])
    paths = session_data.get("request_paths", [])
    if not timestamps or not paths:
        return {"flagged": False, "severity": "none", "count_20s": 0}

    paired = list(zip(timestamps[-len(paths):], paths))
    recent_dashboard = [
        path
        for stamp, path in paired
        if now - stamp <= 20 and path in {"/dashboard", "/api/user/dashboard"}
    ]
    count_20s = len(recent_dashboard)
    if count_20s >= 12:
        return {"flagged": True, "severity": "critical", "count_20s": count_20s}
    if count_20s >= 7:
        return {"flagged": True, "severity": "warning", "count_20s": count_20s}
    return {"flagged": False, "severity": "none", "count_20s": count_20s}


def anonymous_profile(ip_address):
    profile = ANON_TRAFFIC_PROFILES.get(ip_address)
    if profile:
        return profile

    profile = create_session_profile(f"anonymous:{ip_address}", ip_address)
    ANON_TRAFFIC_PROFILES[ip_address] = profile
    return profile


def remember_ip_identity(ip_address, username):
    if not ip_address or not username:
        return
    IP_TO_RECENT_USER[ip_address] = username


def correlated_username_for_ip(ip_address):
    if not ip_address:
        return None
    return IP_TO_RECENT_USER.get(ip_address)


def merge_anonymous_profile_into_user(username, ip_address, user_session):
    anon_profile = ANON_TRAFFIC_PROFILES.get(ip_address)
    if not anon_profile or not user_session:
        return

    # Carry forward suspicious request pressure observed before login from same IP.
    merged_timestamps = list(anon_profile.get("request_timestamps", [])) + list(user_session.get("request_timestamps", []))
    merged_paths = list(anon_profile.get("request_paths", [])) + list(user_session.get("request_paths", []))
    merged_methods = list(anon_profile.get("request_methods", [])) + list(user_session.get("request_methods", []))
    merged_intervals = list(anon_profile.get("request_intervals", [])) + list(user_session.get("request_intervals", []))
    merged_sequence = list(anon_profile.get("sequence_window", [])) + list(user_session.get("sequence_window", []))

    user_session["request_timestamps"] = merged_timestamps[-120:]
    user_session["request_paths"] = merged_paths[-120:]
    user_session["request_methods"] = merged_methods[-120:]
    user_session["request_intervals"] = merged_intervals[-120:]
    user_session["sequence_window"] = merged_sequence[-60:]
    save_session(username, user_session)

    add_admin_alert(
        message=f"Attack traffic fingerprint on IP {ip_address} is now correlated to user {username}.",
        severity="critical",
        username=username,
        ip_address=ip_address,
        action_user=username,
    )

    # Clear stale anonymous identity once mapped to a real user.
    ANON_TRAFFIC_PROFILES.pop(ip_address, None)


def handle_request_flood_signal(actor_label, ip_address, pressure, username=None, profile=None):
    if not pressure.get("flagged"):
        return
    if username and not is_monitoring_enabled(username):
        return

    signal_key = attack_signal_key(actor_label, ip_address)
    if not should_emit_attack_alert(signal_key):
        return

    req10 = pressure.get("requests_last_10s", 0)
    req60 = pressure.get("requests_last_60s", 0)
    cadence = pressure.get("fast_intervals", 0)
    severity = pressure.get("severity", "warning")
    reasons = pressure.get("reasons", [])
    primary_reason = reasons[0] if reasons else "High request pressure detected"
    reason_text = ", ".join(reasons) if reasons else primary_reason
    mapped_username = username or correlated_username_for_ip(ip_address)
    if mapped_username:
        label = f"user {mapped_username}"
    else:
        label = f"anonymous source {ip_address}"

    add_admin_alert(
        message=(
            f"{primary_reason} from {label} ({severity}) "
            f"[10s:{req10}, 60s:{req60}, fast:{cadence}] - {reason_text}"
        ),
        severity=severity,
        username=mapped_username,
        ip_address=ip_address,
        action_user=mapped_username,
    )


def is_trust_locked(trust_score):
    return int(trust_score) <= TRUST_ACTION_LOCK_THRESHOLD


def trust_lock_message(trust_score):
    return (
        f"All dashboard actions are suspended. Your trust score ({int(trust_score)}) "
        f"is below the safety threshold ({TRUST_ACTION_LOCK_THRESHOLD}). Contact admin."
    )


def emit_trust_lock_alert(username, trust_score, current_ip):
    signal_key = f"trust_lock:{username}"
    if not should_emit_attack_alert(signal_key):
        return

    add_admin_alert(
        f"User {username} was auto-suspended (trust score {int(trust_score)} <= "
        f"{TRUST_ACTION_LOCK_THRESHOLD}) from IP {current_ip}."
    )
    log_user_activity(
        username,
        (
            "Dashboard actions auto-suspended by trust policy "
            f"(score {int(trust_score)} <= {TRUST_ACTION_LOCK_THRESHOLD})"
        ),
    )


def enforce_trust_lock(session_data, current_ip, api_mode=False):
    username = session_data.get("username") or current_username() or "unknown"
    monitoring_enabled = is_monitoring_enabled(username)
    if monitoring_enabled:
        risk_state = calculate_behavior_risk(session_data, current_ip)
        if username and username != "unknown":
            update_user_security_snapshot(
                username=username,
                risk=risk_state.get("risk", 0),
                trust_score=risk_state.get("trust_score", 100),
                access_level=risk_state.get("access_level", "full_access"),
            )
    else:
        risk_state = frozen_security_state(session_data, username)
    trust_score = int(risk_state.get("trust_score", 100))
    if not is_trust_locked(trust_score):
        return risk_state, None

    if monitoring_enabled:
        emit_trust_lock_alert(username, trust_score, current_ip)
    message = trust_lock_message(trust_score)
    if api_mode:
        return risk_state, api_error(
            message,
            status=403,
            code="trust_locked",
            trust_score=trust_score,
            threshold=TRUST_ACTION_LOCK_THRESHOLD,
        )

    return risk_state, redirect(
        url_for(
            "dashboard",
            page="overview",
            message=message,
            message_type="error",
        )
    )


@app.before_request
def monitor_anonymous_traffic():
    if request.endpoint == "static":
        return None
    if current_role() in {"user", "admin"} and current_username():
        return None

    current_ip = request.remote_addr or "unknown"
    profile = anonymous_profile(current_ip)
    record_request(
        profile,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    pressure = detect_request_flood(profile)
    handle_request_flood_signal("anonymous", current_ip, pressure, profile=profile)
    return None


@app.after_request
def monitor_authenticated_user_traffic(response):
    username = current_username()
    if not username or current_role() != "user":
        return response

    session_data = get_session(username)
    if not session_data:
        return response
    if not is_monitoring_enabled(username):
        return response

    current_ip = request.remote_addr or "unknown"
    pressure = detect_request_flood(session_data)
    handle_request_flood_signal("user", current_ip, pressure, username=username, profile=session_data)
    refresh_pressure = detect_dashboard_refresh_pressure(session_data)
    if refresh_pressure.get("flagged"):
        refresh_key = f"refresh:{username}:{current_ip}"
        if should_emit_refresh_alert(refresh_key):
            severity = refresh_pressure.get("severity", "warning")
            count_20s = refresh_pressure.get("count_20s", 0)
            add_admin_alert(
                message=(
                    f"Continuous page refreshing detected from user {username} "
                    f"on /dashboard ({count_20s} refreshes in 20s)."
                ),
                severity=severity,
                username=username,
                ip_address=current_ip,
                action_user=username,
            )
            log_user_activity(
                username,
                f"Refresh pressure detected ({count_20s} dashboard requests in 20s, severity={severity})",
            )
    return response


def render_user_dashboard(page="overview"):
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response
    user = get_user(current_username())

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    selected_file = request.args.get("file", "").strip()
    state = build_dashboard_state(session_data, current_ip, selected_file=selected_file)
    user_locked = is_trust_locked(state["trust_score"])

    valid_pages = {"overview", "files", "upload"}
    current_page = page if page in valid_pages else "overview"

    return render_template(
        "dashboard.html",
        user=current_username(),
        login_start=user.get("login_start", COMPANY_LOGIN_START),
        login_end=user.get("login_end", COMPANY_LOGIN_END),
        manual_access_open=manual_access_is_open(user),
        manual_access_until=manual_access_label(user),
        login_window=format_schedule_window(user),
        files=state["files"],
        preview_file=state["preview_file"],
        message=request.args.get("message", ""),
        message_type=request.args.get("message_type", "info"),
        current_page=current_page,
        timeline=session_data["timeline"][-10:],
        max_upload_size_mb=MAX_UPLOAD_SIZE // (1024 * 1024),
        blocked_extensions=", ".join(sorted(SUSPICIOUS_EXTENSIONS)),
        trust_score=state["trust_score"],
        trust_lock_threshold=TRUST_ACTION_LOCK_THRESHOLD,
        user_locked=user_locked,
    )


@app.route("/api/session")
def api_session():
    username = current_username()
    role = current_role()
    if not username or not role:
        return jsonify({"ok": True, "authenticated": False, "user": None, "role": None})
    return jsonify({"ok": True, "authenticated": True, "user": username, "role": role})


@app.route("/api/auth/signup", methods=["POST"])
def api_signup():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    login_start = str(payload.get("login_start", "")).strip()
    login_end = str(payload.get("login_end", "")).strip()

    if not username or not password or not login_start or not login_end:
        return api_error("All signup fields are required.")
    if get_user(username):
        return api_error("That username already exists.", status=409, code="username_exists")
    if not validate_login_hours(login_start, login_end):
        return api_error("Please choose valid login hours.")
    login_start = normalize_time_value(login_start)
    login_end = normalize_time_value(login_end)

    created_user = create_user(username, password, role="user", login_start=login_start, login_end=login_end)
    if not created_user:
        return api_error("We could not create that account. Please try again.", status=500)

    return api_success(
        f"Signup successful for {username}. You can now sign in during {format_schedule_window(created_user)}."
    )


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    selected_role = str(payload.get("role", "user")).strip().lower()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))

    user = get_user(username)
    if user and user["password"] == password and user["role"] == selected_role:
        if user["role"] == "user" and not is_within_login_hours(user):
            return api_error(
                f"You cannot access the platform outside your allowed login hours: {format_schedule_window(user)}.",
                status=403,
                code="outside_login_hours",
            )

        session["user"] = username
        session["role"] = user["role"]
        if user["role"] == "user":
            current_ip = request.remote_addr or "unknown"
            profile = create_session_profile(
                username,
                current_ip,
                user_agent=request.headers.get("User-Agent", ""),
                accept_language=request.headers.get("Accept-Language", ""),
            )
            merge_anonymous_profile_into_user(username, current_ip, profile)
            save_session(username, profile)
            remember_ip_identity(current_ip, username)
            log_user_activity(username, f"Logged in from {current_ip}")
        return api_success("Login successful.", role=user["role"], user=username)

    if user and user["password"] == password and user["role"] != selected_role:
        return api_error(
            f"This account is registered as {user['role']}. Please choose the correct role.",
            status=400,
            code="role_mismatch",
        )
    return api_error("Invalid username or password", status=401, code="invalid_credentials")


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    username = current_username()
    role = current_role()
    if username and role == "user":
        log_user_activity(username, "Logged out")
    session.clear()
    return api_success("Logged out.")


@app.route("/api/user/dashboard")
def api_user_dashboard():
    if current_role() != "user":
        return api_error("Unauthorized", status=401, code="unauthorized")

    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return api_error("Session expired or outside allowed hours.", status=401, code="session_inactive")

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    selected_file = request.args.get("file", "").strip()
    state = build_dashboard_state(session_data, current_ip, selected_file=selected_file)
    user = get_user(current_username()) or {}

    return jsonify(
        {
            "ok": True,
            "user": current_username(),
            "login_start": user.get("login_start", COMPANY_LOGIN_START),
            "login_end": user.get("login_end", COMPANY_LOGIN_END),
            "manual_access_open": manual_access_is_open(user),
            "manual_access_until": manual_access_label(user),
            "login_window": format_schedule_window(user) if user else "Not configured",
            "state": state,
            "user_locked": is_trust_locked(state["trust_score"]),
            "trust_lock_threshold": TRUST_ACTION_LOCK_THRESHOLD,
            "timeline": session_data.get("timeline", [])[-10:],
            "max_upload_size_mb": MAX_UPLOAD_SIZE // (1024 * 1024),
            "blocked_extensions": sorted(SUSPICIOUS_EXTENSIONS),
        }
    )


@app.route("/api/admin/dashboard")
def api_admin_dashboard():
    if current_role() != "admin":
        return api_error("Unauthorized", status=401, code="unauthorized")

    selected_user = request.args.get("user", "").strip()
    sessions = build_admin_sessions(selected_user or None)
    users = build_admin_users(selected_user or None)
    return jsonify(
        {
            "ok": True,
            "admin": current_username(),
            "sessions": sessions,
            "users": users,
            "selected_user": selected_user,
            "user_profile": build_admin_user_profile(selected_user or None, sessions),
            "files": list_shared_files(),
            "admin_alerts": get_admin_alerts(),
        }
    )


@app.route("/api/files/create", methods=["POST"])
def api_create_file():
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return api_error("Unauthorized", status=401, code="unauthorized")

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=True)
    if trust_lock_response:
        return trust_lock_response

    if not can_perform(risk_state["access_level"], "create", risk_state["trust_score"]):
        record_file_event(session_data, "create", "new-file", False, "Create blocked by current access level")
        add_admin_alert(f"Blocked create-file attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), "Create file blocked by security policy")
        return api_error("Action denied by security policy.", status=403, code="blocked")

    payload = request.get_json(silent=True) or {}
    filename = secure_filename(str(payload.get("filename", "")))
    content = str(payload.get("content", ""))
    if not filename:
        return api_error("Filename is required.")
    existing_target = SHARED_DIR / filename
    if existing_target.exists() and not user_can_access_file(current_username(), filename):
        return api_error("You cannot overwrite another user's file.", status=403, code="forbidden_file")

    suspicious, reason = inspect_file(filename)
    if suspicious:
        record_file_event(session_data, "create", filename, False, reason, suspicious=True)
        add_admin_alert(f"Suspicious file create blocked for {current_username()}: {filename}")
        log_user_activity(current_username(), f"Suspicious create blocked: {filename}")
        return api_error("Action denied by security policy.", status=403, code="suspicious_file")

    target = SHARED_DIR / filename
    target.write_text(content, encoding="utf-8")
    set_file_owner(filename, current_username())
    record_file_event(session_data, "create", filename, True)
    log_user_activity(current_username(), f"Created file: {filename}")
    return api_success("Shared file created.", filename=filename)


@app.route("/api/files/update", methods=["POST"])
def api_update_file():
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return api_error("Unauthorized", status=401, code="unauthorized")

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=True)
    if trust_lock_response:
        return trust_lock_response
    payload = request.get_json(silent=True) or {}

    filename = str(payload.get("filename", ""))
    target = safe_shared_path(filename)
    if not target or not target.exists():
        return api_error("File not found.", status=404, code="missing_file")
    if not user_can_access_file(current_username(), target.name):
        return api_error("You are not allowed to access this file.", status=403, code="forbidden_file")

    if not can_perform(risk_state["access_level"], "update", risk_state["trust_score"]):
        record_file_event(session_data, "update", target.name, False, "Update blocked by current access level")
        add_admin_alert(f"Blocked update-file attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), f"Update blocked by security policy: {target.name}")
        return api_error("Action denied by security policy.", status=403, code="blocked")

    target.write_text(str(payload.get("content", "")), encoding="utf-8")
    record_file_event(session_data, "update", target.name, True)
    log_user_activity(current_username(), f"Updated file: {target.name}")
    return api_success("File updated successfully.", filename=target.name)


@app.route("/api/files/delete/<filename>", methods=["POST"])
def api_delete_file(filename):
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return api_error("Unauthorized", status=401, code="unauthorized")

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=True)
    if trust_lock_response:
        return trust_lock_response
    target = safe_shared_path(filename)

    if not target or not target.exists():
        return api_error("File not found.", status=404, code="missing_file")
    if not user_can_access_file(current_username(), target.name):
        return api_error("You are not allowed to access this file.", status=403, code="forbidden_file")
    if not can_perform(risk_state["access_level"], "delete", risk_state["trust_score"]):
        record_file_event(session_data, "delete", target.name, False, "Delete blocked by current access level")
        add_admin_alert(f"Blocked delete-file attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), f"Delete blocked by security policy: {target.name}")
        return api_error("Action denied by security policy.", status=403, code="blocked")

    target.unlink()
    remove_file_owner(target.name)
    record_file_event(session_data, "delete", target.name, True)
    log_user_activity(current_username(), f"Deleted file: {target.name}")
    return api_success("File deleted successfully.", filename=target.name)


@app.route("/api/files/upload", methods=["POST"])
def api_upload_file():
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return api_error("Unauthorized", status=401, code="unauthorized")

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=True)
    if trust_lock_response:
        return trust_lock_response

    if not can_perform(risk_state["access_level"], "upload", risk_state["trust_score"]):
        record_file_event(session_data, "upload", "unknown", False, "Upload blocked by current access level")
        add_admin_alert(f"Blocked upload attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), "Upload blocked by security policy")
        return api_error("Action denied by security policy.", status=403, code="blocked")

    file = request.files.get("shared_file")
    if not file or not file.filename:
        return api_error("Choose a file first.")

    filename = secure_filename(file.filename)
    existing_target = SHARED_DIR / filename
    if existing_target.exists() and not user_can_access_file(current_username(), filename):
        return api_error("You cannot overwrite another user's file.", status=403, code="forbidden_file")
    file_size = upload_size(file)
    if file_size > MAX_UPLOAD_SIZE:
        add_admin_alert(f"Unusually large file uploaded from {current_username()}: {filename} ({file_size} bytes)")
        record_file_event(
            session_data,
            "upload",
            filename,
            False,
            "Upload blocked because file size exceeded 10 MB",
            suspicious=True,
        )
        return api_error("Upload denied. Files larger than 10 MB are not allowed.", status=400, code="too_large")

    suspicious, reason = inspect_file(filename)
    if suspicious:
        add_admin_alert(f"Suspicious file upload blocked for {current_username()}: {filename}")
        log_user_activity(current_username(), f"Suspicious upload blocked: {filename}")
        record_file_event(session_data, "upload", filename, False, reason, suspicious=True)
        return api_error(reason, status=400, code="suspicious_file")

    target = SHARED_DIR / filename
    file.save(target)
    set_file_owner(filename, current_username())
    record_file_event(session_data, "upload", filename, True)
    log_user_activity(current_username(), f"Uploaded file: {filename}")
    return api_success("File uploaded successfully.", filename=filename)


@app.route("/", methods=["GET", "POST"])
def login():
    error = request.args.get("error", "")
    message = request.args.get("message", "")
    selected_role = "user"
    selected_mode = "login"
    selected_username = ""
    if request.method == "POST":
        selected_mode = request.form.get("auth_action", "login").strip().lower()
        if selected_mode == "signup":
            username = request.form.get("signup_username", "").strip()
            password = request.form.get("signup_password", "")
            login_start = request.form.get("login_start", "").strip()
            login_end = request.form.get("login_end", "").strip()

            if not username or not password or not login_start or not login_end:
                error = "All signup fields are required."
            elif get_user(username):
                error = "That username already exists."
            elif not validate_login_hours(login_start, login_end):
                error = "Please choose valid login hours."
            else:
                login_start = normalize_time_value(login_start)
                login_end = normalize_time_value(login_end)
                created_user = create_user(username, password, role="user", login_start=login_start, login_end=login_end)
                if created_user:
                    return redirect(
                        url_for(
                            "login",
                            message=f"Signup successful for {username}. You can now sign in during {format_schedule_window(created_user)}.",
                        )
                    )
                error = "We could not create that account. Please try again."
        else:
            selected_role = request.form.get("role", "user").strip().lower()
            username = request.form.get("username", "").strip()
            selected_username = username
            password = request.form["password"]
            user = get_user(username)

            if user and user["password"] == password and user["role"] == selected_role:
                if user["role"] == "user" and not is_within_login_hours(user):
                    error = f"You cannot access the platform outside your allowed login hours: {format_schedule_window(user)}."
                else:
                    session["user"] = username
                    session["role"] = user["role"]
                    if user["role"] == "user":
                        current_ip = request.remote_addr or "unknown"
                        profile = create_session_profile(
                            username,
                            current_ip,
                            user_agent=request.headers.get("User-Agent", ""),
                            accept_language=request.headers.get("Accept-Language", ""),
                        )
                        merge_anonymous_profile_into_user(username, current_ip, profile)
                        save_session(username, profile)
                        remember_ip_identity(current_ip, username)
                        log_user_activity(username, f"Logged in from {current_ip}")
                    return redirect(url_for(dashboard_route_for_role(user["role"])))

            if user and user["password"] == password and user["role"] != selected_role:
                error = f"This account is registered as {user['role']}. Please choose the correct role."
            elif not error:
                error = "Invalid username or password"

    return render_template(
        "login.html",
        error=error,
        message=message,
        selected_role=selected_role,
        selected_mode=selected_mode,
        selected_username=selected_username,
        default_login_start=COMPANY_LOGIN_START,
        default_login_end=COMPANY_LOGIN_END,
    )


@app.route("/dashboard")
def dashboard():
    if current_role() != "user":
        return redirect(url_for("login"))
    login_window_redirect = enforce_user_login_hours()
    if login_window_redirect:
        return login_window_redirect

    page = request.args.get("page", "overview").strip().lower()
    return render_user_dashboard(page=page)


@app.route("/admin/dashboard")
def admin_dashboard():
    if current_role() != "admin":
        return redirect(url_for("login"))

    selected_user = request.args.get("user", "").strip()

    sessions = build_admin_sessions(selected_user or None)
    users = build_admin_users(selected_user or None)

    return render_template(
        "admin_dashboard.html",
        admin=current_username(),
        sessions=sessions,
        users=users,
        selected_user=selected_user,
        user_profile=build_admin_user_profile(selected_user or None, sessions),
        files=list_shared_files(),
        admin_alerts=get_admin_alerts(),
        message=request.args.get("message", ""),
        message_type=request.args.get("message_type", "info"),
    )


@app.route("/user/login-hours", methods=["POST"])
def update_login_hours():
    return redirect(
        url_for(
            "dashboard",
            message="Login hours are view-only for users. Contact admin to change access windows.",
            message_type="info",
        )
    )


@app.route("/admin/users/<username>/open-access", methods=["POST"])
def open_access(username):
    if current_role() != "admin":
        return redirect(url_for("login"))

    return_user = request.form.get("return_user", "").strip()
    access_start = request.form.get("access_start", "").strip()
    access_end = request.form.get("access_end", "").strip()

    if not validate_login_hours(access_start, access_end):
        return admin_response(
            "Please enter valid access start and end times.",
            message_type="error",
            status=400,
            selected_user=return_user,
        )
    access_start = normalize_time_value(access_start)
    access_end = normalize_time_value(access_end)

    if access_start == access_end:
        return admin_response(
            "Access start and end time cannot be the same.",
            message_type="error",
            status=400,
            selected_user=return_user,
        )

    user = open_user_access(username, access_start, access_end)
    if not user:
        return admin_response("User not found.", message_type="error", status=404, selected_user=return_user)

    log_user_activity(username, f"Admin set manual access window to {access_start} - {access_end}")
    return admin_response(
        f"Access window set for {username}: {manual_access_label(user)}.",
        message_type="success",
        selected_user=return_user or username,
    )


@app.route("/admin/users/<username>/close-access", methods=["POST"])
def close_access(username):
    if current_role() != "admin":
        return redirect(url_for("login"))

    return_user = request.form.get("return_user", "").strip()
    user = close_user_access(username)
    if not user:
        return admin_response("User not found.", message_type="error", status=404, selected_user=return_user)

    log_user_activity(username, "Admin closed manual access window")
    return admin_response(
        f"Manual access closed for {username}.",
        message_type="success",
        selected_user=return_user or username,
    )


@app.route("/admin/users/<username>/monitoring", methods=["POST"])
def update_monitoring(username):
    if current_role() != "admin":
        return redirect(url_for("login"))

    enabled = request.form.get("enabled") == "1"
    user = set_user_monitoring(username, enabled)
    if not user:
        return admin_response("User not found.", message_type="error", status=404)

    state_label = "enabled" if enabled else "disabled"
    log_user_activity(username, f"Admin {state_label} monitoring")
    selected_user = request.form.get("return_user", "").strip() or request.args.get("user", "").strip()
    return admin_response(
        f"Monitoring {state_label} for {username}.",
        message_type="success",
        selected_user=selected_user or username,
    )


@app.route("/admin/alerts/<int:alert_index>/dismiss", methods=["POST"])
def dismiss_alert(alert_index):
    if current_role() != "admin":
        return redirect(url_for("login"))

    if not dismiss_admin_alert(alert_index):
        return admin_response("Alert was already dismissed.", message_type="error", status=404)
    return admin_response("Alert dismissed.", message_type="success")


@app.route("/files/upload", methods=["POST"])
def upload_file():
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=False)
    if trust_lock_response:
        return trust_lock_response

    if not can_perform(risk_state["access_level"], "upload", risk_state["trust_score"]):
        record_file_event(session_data, "upload", "unknown", False, "Upload blocked by current access level")
        add_admin_alert(f"Blocked upload attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), "Upload blocked by security policy")
        return redirect(
            url_for("dashboard", message="Action denied by security policy.", message_type="error")
        )

    file = request.files.get("shared_file")
    if not file or not file.filename:
        return redirect(url_for("dashboard", message="Choose a file first.", message_type="error"))

    filename = secure_filename(file.filename)
    existing_target = SHARED_DIR / filename
    if existing_target.exists() and not user_can_access_file(current_username(), filename):
        return redirect(url_for("dashboard", message="You cannot overwrite another user's file.", message_type="error"))
    file_size = upload_size(file)
    if file_size > MAX_UPLOAD_SIZE:
        add_admin_alert(
            f"Unusually large file uploaded from {current_username()}: {filename} ({file_size} bytes)"
        )
        record_file_event(
            session_data,
            "upload",
            filename,
            False,
            "Upload blocked because file size exceeded 10 MB",
            suspicious=True,
        )
        return redirect(
            url_for(
                "dashboard",
                message="Upload denied. Files larger than 10 MB are not allowed.",
                message_type="error",
            )
        )

    suspicious, reason = inspect_file(filename)
    if suspicious:
        add_admin_alert(f"Suspicious file upload blocked for {current_username()}: {filename}")
        log_user_activity(current_username(), f"Suspicious upload blocked: {filename}")
        record_file_event(session_data, "upload", filename, False, reason, suspicious=True)
        return redirect(
            url_for(
                "dashboard",
                message=reason,
                message_type="error",
            )
        )

    target = SHARED_DIR / filename
    file.save(target)
    set_file_owner(filename, current_username())
    record_file_event(session_data, "upload", filename, True)
    log_user_activity(current_username(), f"Uploaded file: {filename}")
    return redirect(
        url_for(
            "dashboard",
            page="files",
            file=filename,
            message="File uploaded successfully. Showing preview.",
            message_type="success",
        )
    )


@app.route("/files/create", methods=["POST"])
def create_file():
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=False)
    if trust_lock_response:
        return trust_lock_response

    if not can_perform(risk_state["access_level"], "create", risk_state["trust_score"]):
        record_file_event(session_data, "create", "new-file", False, "Create blocked by current access level")
        add_admin_alert(f"Blocked create-file attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), "Create file blocked by security policy")
        return redirect(
            url_for("dashboard", message="Action denied by security policy.", message_type="error")
        )

    filename = secure_filename(request.form.get("filename", ""))
    content = request.form.get("content", "")
    if not filename:
        return redirect(url_for("dashboard", message="Filename is required.", message_type="error"))
    existing_target = SHARED_DIR / filename
    if existing_target.exists() and not user_can_access_file(current_username(), filename):
        return redirect(url_for("dashboard", message="You cannot overwrite another user's file.", message_type="error"))

    suspicious, reason = inspect_file(filename)
    if suspicious:
        record_file_event(session_data, "create", filename, False, reason, suspicious=True)
        add_admin_alert(f"Suspicious file create blocked for {current_username()}: {filename}")
        log_user_activity(current_username(), f"Suspicious create blocked: {filename}")
        return redirect(
            url_for("dashboard", message="Action denied by security policy.", message_type="error")
        )

    target = SHARED_DIR / filename
    target.write_text(content, encoding="utf-8")
    set_file_owner(filename, current_username())
    record_file_event(session_data, "create", filename, True)
    log_user_activity(current_username(), f"Created file: {filename}")
    return redirect(
        url_for(
            "dashboard",
            page="files",
            message="Shared file created.",
            message_type="success",
            file=filename,
        )
    )


@app.route("/files/update", methods=["POST"])
def update_file():
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=False)
    if trust_lock_response:
        return trust_lock_response

    filename = request.form.get("filename", "")
    target = safe_shared_path(filename)
    if not target or not target.exists():
        return redirect(url_for("dashboard", message="File not found.", message_type="error"))
    if not user_can_access_file(current_username(), target.name):
        return redirect(url_for("dashboard", message="You can only edit your own files.", message_type="error"))

    if not can_perform(risk_state["access_level"], "update", risk_state["trust_score"]):
        record_file_event(session_data, "update", target.name, False, "Update blocked by current access level")
        add_admin_alert(f"Blocked update-file attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), f"Update blocked by security policy: {target.name}")
        return redirect(url_for("dashboard", message="Action denied by security policy.", message_type="error"))

    content = request.form.get("content", "")
    target.write_text(content, encoding="utf-8")
    record_file_event(session_data, "update", target.name, True)
    log_user_activity(current_username(), f"Updated file: {target.name}")
    return redirect(
        url_for(
            "dashboard",
            page="files",
            message="File updated successfully.",
            message_type="success",
            file=target.name,
        )
    )


@app.route("/files/delete/<filename>", methods=["POST"])
def delete_file(filename):
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=False)
    if trust_lock_response:
        return trust_lock_response

    target = safe_shared_path(filename)
    if not target or not target.exists():
        return redirect(url_for("dashboard", message="File not found.", message_type="error"))
    if not user_can_access_file(current_username(), target.name):
        return redirect(url_for("dashboard", message="You can only delete your own files.", message_type="error"))

    if not can_perform(risk_state["access_level"], "delete", risk_state["trust_score"]):
        record_file_event(session_data, "delete", target.name, False, "Delete blocked by current access level")
        add_admin_alert(f"Blocked delete-file attempt by {current_username()} due to security policy.")
        log_user_activity(current_username(), f"Delete blocked by security policy: {target.name}")
        return redirect(url_for("dashboard", message="Action denied by security policy.", message_type="error"))

    target.unlink()
    remove_file_owner(target.name)
    record_file_event(session_data, "delete", target.name, True)
    log_user_activity(current_username(), f"Deleted file: {target.name}")
    return redirect(url_for("dashboard", page="files", message="File deleted successfully.", message_type="success"))


@app.route("/files/view/<filename>")
def view_file(filename):
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=False)
    if trust_lock_response:
        return trust_lock_response

    target = safe_shared_path(filename)
    if not target or not target.exists():
        return redirect(url_for("dashboard", message="File not found.", message_type="error"))
    if not user_can_access_file(current_username(), target.name):
        return redirect(url_for("dashboard", message="You can only view your own files.", message_type="error"))

    if not can_perform(risk_state["access_level"], "view", risk_state["trust_score"]):
        record_file_event(session_data, "view", filename, False, "View blocked by current access level")
        add_admin_alert(f"Blocked file preview by {current_username()} due to security policy.")
        log_user_activity(current_username(), f"View blocked by security policy: {filename}")
        return redirect(url_for("dashboard", message="Action denied by security policy.", message_type="error"))

    record_file_event(session_data, "view", target.name, True)
    log_user_activity(current_username(), f"Viewed file: {target.name}")
    return redirect(
        url_for(
            "dashboard",
            page="files",
            file=target.name,
            message="Showing file preview.",
            message_type="info",
        )
    )


@app.route("/files/raw/<filename>")
def raw_file(filename):
    session_data, blocked_response = require_active_user_session()
    if blocked_response:
        return blocked_response

    current_ip = request.remote_addr or "unknown"
    record_request(
        session_data,
        current_ip,
        request.path,
        request.method,
        user_agent=request.headers.get("User-Agent", ""),
        accept_language=request.headers.get("Accept-Language", ""),
    )
    risk_state, trust_lock_response = enforce_trust_lock(session_data, current_ip, api_mode=False)
    if trust_lock_response:
        return trust_lock_response
    target = safe_shared_path(filename)
    if not target or not target.exists():
        return redirect(url_for("dashboard", message="File not found.", message_type="error"))
    if not user_can_access_file(current_username(), target.name):
        return redirect(url_for("dashboard", message="You can only view your own files.", message_type="error"))

    if not can_perform(risk_state["access_level"], "view", risk_state["trust_score"]):
        record_file_event(session_data, "view", filename, False, "Inline preview blocked by current access level")
        add_admin_alert(f"Blocked inline file preview by {current_username()} due to security policy.")
        log_user_activity(current_username(), f"Inline view blocked by security policy: {filename}")
        return redirect(url_for("dashboard", message="Action denied by security policy.", message_type="error"))

    return send_file(target, as_attachment=False, download_name=target.name)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    username = current_username()
    role = current_role()
    if username and role == "user":
        log_user_activity(username, "Logged out")
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    Path(SHARED_DIR).mkdir(exist_ok=True)
    bind_host = "0.0.0.0"
    bind_port = 5000
    print_startup_access_urls(bind_host, bind_port)
    app.run(host=bind_host, port=bind_port, debug=True)
