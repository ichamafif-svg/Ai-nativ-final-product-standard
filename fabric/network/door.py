"""The product's one door (D68), run inside the bac: a Unix socket in, the product's own port out.

    python -I door.py SOCKET PORT [--egress EGRESS_SOCKET] -- COMMAND...

It starts the product with PORT in its environment (it listens on 127.0.0.1:$PORT of its own empty network, as
anywhere else), then moves bytes between connections on SOCKET, which the platform reaches from outside the bac,
and 127.0.0.1:PORT. It adds no network: the bac still has none. It decides nothing and is not trusted: it runs with
the product and can only affect the product's own inbound traffic. It ends when the product ends.
With --egress, it also relays 127.0.0.1:3128 (the HTTPS_PROXY the platform sets) to the egress socket the platform
mounted: the bac's one way out, toward the egress proxy. Code that ignores the proxy still has no route.

Stdlib only: it runs on the bac's Python, before anything of the product is importable.
"""
import os
import socket
import subprocess
import sys
import threading

CHUNK = 65536


def pump(src, dst):
    try:
        while True:
            data = src.recv(CHUNK)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def serve(listener, port: int):
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        try:
            upstream = socket.create_connection(("127.0.0.1", port), timeout=5)
            upstream.settimeout(None)
        except OSError:
            client.close()
            continue
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


def relay_out(egress: str, port: int = 3128):
    out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    out.bind(("127.0.0.1", port))
    out.listen(128)
    while True:
        try:
            client, _ = out.accept()
        except OSError:
            return
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(egress)
        except OSError:
            client.close()
            continue
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


def main(argv):
    path, port, *rest = argv
    egress = None
    if rest[:1] == ["--egress"]:
        egress, rest = rest[1], rest[2:]
    sep, *command = rest or [None]
    if sep != "--" or not command:
        raise SystemExit("usage: door.py SOCKET PORT [--egress EGRESS_SOCKET] -- COMMAND...")
    if egress:
        threading.Thread(target=relay_out, args=(egress,), daemon=True).start()
    if os.path.exists(path):
        os.unlink(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o666)
    listener.listen(128)
    product = subprocess.Popen(command, env={**os.environ, "PORT": port})
    threading.Thread(target=serve, args=(listener, int(port)), daemon=True).start()
    code = product.wait()
    listener.close()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
