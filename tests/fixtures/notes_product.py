"""A product that stores notes in the platform's PostgreSQL, acting for whoever the gateway says is calling."""
import json
import os
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PSQL = "/usr/lib/postgresql/16/bin/psql"


def sql(statement: str) -> tuple[int, str]:
    done = subprocess.run([PSQL, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", statement],
                          capture_output=True, text=True, timeout=30)
    return done.returncode, (done.stdout if done.returncode == 0 else done.stderr).strip()


class Notes(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def reply(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        token = self.headers.get("x-standard-identity", "").replace("'", "")
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        if self.path.startswith("/setup"):
            return self.reply(sql("CREATE TABLE IF NOT EXISTS notes (id serial primary key, owner_id text, body text)"))
        act = f"SELECT standard.act_as('{token}');" if token else ""
        if self.path.startswith("/add"):
            owner = q.get("owner", "")
            return self.reply(sql(f"BEGIN; {act} INSERT INTO notes(owner_id, body) VALUES ('{owner}', 'x'); COMMIT;"))
        return self.reply(sql(f"BEGIN; {act} SELECT owner_id FROM notes ORDER BY id; COMMIT;"))


ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), Notes).serve_forever()
