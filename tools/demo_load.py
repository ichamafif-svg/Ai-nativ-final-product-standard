"""Steady traffic on the demo service, so that the console has something real to show.

    python tools/demo_load.py [http://127.0.0.1:9000] [requests-per-second]
"""
import random
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9000"
RATE = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
MIX = [("GET", "/health", 2), ("GET", "/users/{n}", 10), ("GET", "/search?q=chaise", 4), ("POST", "/orders", 3),
       ("GET", "/orders/{n}", 5)]


def hit(method, path):
    req = urllib.request.Request(BASE + path.replace("{n}", str(random.randint(1, 9999))), method=method,
                                 data=b"{}" if method == "POST" else None)
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError:
        pass
    except OSError:
        time.sleep(1)


while True:
    method, path, _ = random.choices(MIX, weights=[w for *_, w in MIX])[0]
    threading.Thread(target=hit, args=(method, path), daemon=True).start()
    time.sleep(random.expovariate(RATE))
