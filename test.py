import os
import socket

import requests


def detect_local_ipv4():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        ip_address = probe.getsockname()[0]
        if ip_address:
            return ip_address
    except OSError:
        pass
    finally:
        probe.close()

    return "127.0.0.1"


base_url = os.getenv("APP_BASE_URL", f"http://{detect_local_ipv4()}:5000")
for i in range(200):
    requests.get(f"{base_url}/", timeout=5)
