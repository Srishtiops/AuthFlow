import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

DEFAULT_USERS = {
    "user1": {
        "password": "pass123",
        "role": "user",
        "login_start": "08:00",
        "login_end": "17:00",
        "manual_access_start": None,
        "manual_access_end": None,
        "monitoring_enabled": True,
        "last_risk_score": 0,
        "last_trust_score": 100,
        "last_access_level": "full_access",
        "activity_logs": []
    },
    "admin": {"password": "admin123", "role": "admin"},
}
SESSIONS = {}
ADMIN_ALERTS = []
SHARED_DIR = Path(__file__).resolve().parent / "shared_files"
USERS_FILE = Path(__file__).resolve().parent / "users.json"
FILE_META_FILE = Path(__file__).resolve().parent / "file_metadata.json"
COMPANY_LOGIN_START = "08:00"
COMPANY_LOGIN_END = "17:00"
SHARED_DIR.mkdir(exist_ok=True)


def normalize_users(users):
    normalized = {}
    for username, user in (users or {}).items():
        if not isinstance(user, dict):
            continue

        role = user.get("role", "user")
        record = {
            "password": user.get("password", ""),
            "role": role,
        }
        if role == "user":
            record["login_start"] = COMPANY_LOGIN_START
            record["login_end"] = COMPANY_LOGIN_END
            manual_access_start = user.get("manual_access_start")
            manual_access_end = user.get("manual_access_end")
            for field_name, field_value in (("manual_access_start", manual_access_start), ("manual_access_end", manual_access_end)):
                if field_value:
                    try:
                        datetime.strptime(field_value, "%H:%M")
                    except (TypeError, ValueError):
                        if field_name == "manual_access_start":
                            manual_access_start = None
                        else:
                            manual_access_end = None
            record["manual_access_start"] = manual_access_start
            record["manual_access_end"] = manual_access_end
            record["monitoring_enabled"] = bool(user.get("monitoring_enabled", True))
            record["last_risk_score"] = int(user.get("last_risk_score", 0))
            record["last_trust_score"] = int(user.get("last_trust_score", 100))
            record["last_access_level"] = user.get("last_access_level", "full_access")
            activity_logs = user.get("activity_logs", [])
            if not isinstance(activity_logs, list):
                activity_logs = []
            record["activity_logs"] = [str(entry) for entry in activity_logs][-500:]
        normalized[username] = record
    return normalized


def load_users():
    if USERS_FILE.exists():
        try:
            stored = json.loads(USERS_FILE.read_text(encoding="utf-8"))
            users = normalize_users(stored)
            if users:
                return users
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass

    users = normalize_users(deepcopy(DEFAULT_USERS))
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")
    return users


def persist_users():
    USERS_FILE.write_text(json.dumps(USERS, indent=2), encoding="utf-8")


USERS = load_users()


def load_file_metadata():
    if FILE_META_FILE.exists():
        try:
            stored = json.loads(FILE_META_FILE.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                return {str(name): data for name, data in stored.items() if isinstance(data, dict)}
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    return {}


def persist_file_metadata():
    FILE_META_FILE.write_text(json.dumps(FILE_METADATA, indent=2), encoding="utf-8")


FILE_METADATA = load_file_metadata()


def get_user(username):
    return USERS.get(username)


def get_all_users():
    return USERS


def create_user(username, password, role="user", login_start=COMPANY_LOGIN_START, login_end=COMPANY_LOGIN_END):
    if username in USERS:
        return None

    USERS[username] = {
        "password": password,
        "role": role,
        "login_start": COMPANY_LOGIN_START,
        "login_end": COMPANY_LOGIN_END,
        "manual_access_start": None,
        "manual_access_end": None,
        "monitoring_enabled": True,
        "last_risk_score": 0,
        "last_trust_score": 100,
        "last_access_level": "full_access",
        "activity_logs": [],
    }
    persist_users()
    return USERS[username]


def get_user_password(username):
    user = get_user(username)
    return user["password"] if user else None


def get_user_role(username):
    user = get_user(username)
    return user["role"] if user else None


def save_session(username, session_data):
    SESSIONS[username] = session_data
    return session_data


def get_session(username):
    return SESSIONS.get(username)


def get_all_sessions():
    return SESSIONS


def update_user_hours(username, login_start, login_end):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return None

    user["login_start"] = COMPANY_LOGIN_START
    user["login_end"] = COMPANY_LOGIN_END
    persist_users()
    return user


def open_user_access(username, access_start, access_end):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return None

    user["manual_access_start"] = access_start
    user["manual_access_end"] = access_end
    persist_users()
    return user


def close_user_access(username):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return None

    user["manual_access_start"] = None
    user["manual_access_end"] = None
    persist_users()
    return user


def set_user_monitoring(username, enabled):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return None

    user["monitoring_enabled"] = bool(enabled)
    persist_users()
    return user


def append_user_activity(username, message, now=None):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return None

    now = now or datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    user.setdefault("activity_logs", []).append(entry)
    user["activity_logs"] = user["activity_logs"][-500:]
    persist_users()
    return entry


def update_user_security_snapshot(username, risk, trust_score, access_level):
    user = get_user(username)
    if not user or user.get("role") != "user":
        return None

    next_risk = int(risk)
    next_trust = int(trust_score)
    next_access = str(access_level)

    if (
        int(user.get("last_risk_score", 0)) == next_risk
        and int(user.get("last_trust_score", 100)) == next_trust
        and str(user.get("last_access_level", "full_access")) == next_access
    ):
        return user

    user["last_risk_score"] = next_risk
    user["last_trust_score"] = next_trust
    user["last_access_level"] = next_access
    persist_users()
    return user


def add_admin_alert(message, severity="warning", username=None, ip_address=None, action_user=None):
    if isinstance(message, dict):
        alert_entry = {
            "message": str(message.get("message", "")).strip(),
            "severity": str(message.get("severity", "warning")),
            "username": message.get("username"),
            "ip_address": message.get("ip_address"),
            "action_user": message.get("action_user"),
        }
    else:
        alert_entry = {
            "message": str(message).strip(),
            "severity": str(severity or "warning"),
            "username": username,
            "ip_address": ip_address,
            "action_user": action_user,
        }
    ADMIN_ALERTS.insert(0, alert_entry)
    del ADMIN_ALERTS[8:]
    return ADMIN_ALERTS


def get_admin_alerts():
    normalized = []
    for entry in ADMIN_ALERTS:
        if isinstance(entry, dict):
            normalized.append(
                {
                    "message": str(entry.get("message", "")).strip(),
                    "severity": str(entry.get("severity", "warning")),
                    "username": entry.get("username"),
                    "ip_address": entry.get("ip_address"),
                    "action_user": entry.get("action_user"),
                }
            )
        else:
            normalized.append(
                {
                    "message": str(entry).strip(),
                    "severity": "warning",
                    "username": None,
                    "ip_address": None,
                    "action_user": None,
                }
            )
    return normalized


def dismiss_admin_alert(index):
    if index < 0 or index >= len(ADMIN_ALERTS):
        return False
    del ADMIN_ALERTS[index]
    return True


def list_shared_files():
    files = []
    for path in sorted(SHARED_DIR.iterdir()):
        if path.is_file():
            metadata = FILE_METADATA.get(path.name, {})
            files.append(
                {
                    "name": path.name,
                    "size": path.stat().st_size,
                    "modified": path.stat().st_mtime,
                    "owner": metadata.get("owner"),
                }
            )
    return files


def set_file_owner(filename, owner):
    FILE_METADATA[filename] = {"owner": owner}
    persist_file_metadata()


def remove_file_owner(filename):
    if filename in FILE_METADATA:
        del FILE_METADATA[filename]
        persist_file_metadata()


def get_file_owner(filename):
    metadata = FILE_METADATA.get(filename, {})
    return metadata.get("owner")
