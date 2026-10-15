"""A fake OpenID Connect provider for tests: it signs in whoever asks, as `alice` in group `admin`.

/authorize redirects straight back with a code; /token answers an RS256 id_token for that code; /jwks publishes the
key. It checks the PKCE verifier against the challenge, so a sign-in without PKCE fails here too."""
import base64
import hashlib
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64int(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Provider:
    def __init__(self, port: int, client_id: str = "shop"):
        self.port, self.client_id, self.codes = port, client_id, {}
        self.issuer = f"http://127.0.0.1:{port}"

    def serve(self):
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _json(self, body):
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(url.query))
                if url.path == "/authorize":
                    code = base64.urlsafe_b64encode(hashlib.sha256(q["state"].encode()).digest()).decode()[:20]
                    provider.codes[code] = {"challenge": q.get("code_challenge"), "nonce": q.get("nonce")}
                    target = f"{q['redirect_uri']}?code={code}&state={urllib.parse.quote(q['state'])}"
                    self.send_response(302)
                    self.send_header("location", target)
                    self.send_header("content-length", "0")
                    self.end_headers()
                elif url.path == "/jwks":
                    pub = KEY.public_key().public_numbers()
                    self._json({"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                                          "n": b64int(pub.n), "e": b64int(pub.e)}]})
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["content-length"])).decode()))
                grant = provider.codes.pop(form.get("code"), None)
                verifier = form.get("code_verifier", "")
                proof = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                if grant is None or grant["challenge"] != proof:
                    self.send_response(400)
                    self.end_headers()
                    return
                now = int(time.time())
                claims = {"iss": provider.issuer, "aud": provider.client_id, "sub": "alice", "email": "alice@example.com",
                          "email_verified": True, "groups": ["admin"], "iat": now, "exp": now + 300}
                if grant["nonce"]:
                    claims["nonce"] = grant["nonce"]
                token = jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})
                self._json({"access_token": "opaque", "token_type": "Bearer", "expires_in": 300, "id_token": token})

        server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server
