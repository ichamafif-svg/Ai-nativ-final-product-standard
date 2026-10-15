"""Data filtering by the database itself (D68 step 4): PostgreSQL row-level security on the platform's identity.

The product reaches PostgreSQL only through a Unix socket the platform mounts into the bac (no TCP listener at all),
as the role `product`, with no password: nothing in the bac could leak one. Within each transaction it states who it
acts for with `SELECT standard.act_as(<the x-standard-identity token it received>)`: PostgreSQL verifies the
platform's signature itself (Ed25519, in PL/Python, a language the product cannot write functions in) and keeps the
subject where the product cannot write. Policies read `standard.current_subject()`.

A table the product creates with an `owner_id` column (or `tenant_id`) is taken over at once by an event trigger:
owned by the platform, row-level security enabled and forced, one policy per column, data rights granted back to the
product. The product cannot disable, drop or bypass the policy: it no longer owns the table. Forgetting `act_as`
fails closed: no subject, no row.

Known limits: a table without either column is the product's own and unfiltered (the rule AUTHZ-SUBJECT asks for the
column); schema changes to a protected table go through the platform.
"""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

PG = Path("/usr/lib/postgresql/16/bin")

SETUP = r"""
CREATE EXTENSION IF NOT EXISTS plpython3u;
CREATE ROLE standard_owner NOLOGIN;
CREATE ROLE product LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
CREATE DATABASE product OWNER product;
"""

SCHEMA = r"""
CREATE SCHEMA standard AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA standard FROM PUBLIC;
GRANT USAGE ON SCHEMA standard TO product;
CREATE TABLE standard.identity_key (audience text PRIMARY KEY, public_pem text NOT NULL);
REVOKE ALL ON standard.identity_key FROM PUBLIC;

CREATE FUNCTION standard.act_as(token text) RETURNS text
LANGUAGE plpython3u SECURITY DEFINER SET search_path = pg_catalog AS $$
import base64, json, time
from cryptography.hazmat.primitives import serialization
def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
try:
    head, body, sig = token.split(".")
    if json.loads(unb64(head)).get("alg") != "EdDSA":
        raise ValueError("alg")
    claims = json.loads(unb64(body))
    row = plpy.execute(plpy.prepare("SELECT public_pem FROM standard.identity_key WHERE audience = $1", ["text"]),
                       [claims.get("aud")])
    if not row:
        raise ValueError("audience")
    serialization.load_pem_public_key(row[0]["public_pem"].encode()).verify(unb64(sig), f"{head}.{body}".encode())
    if claims.get("iss") != "standard-gateway" or not claims["iat"] <= time.time() < claims["exp"]:
        raise ValueError("time")
except Exception:
    GD.pop("standard_subject", None)
    plpy.error("identity refused")
GD["standard_subject"] = (plpy.execute("SELECT txid_current() AS x")[0]["x"], claims["sub"],
                          claims.get("tenant"), list(claims.get("groups", [])))
return claims["sub"]
$$;

CREATE FUNCTION standard.current_subject() RETURNS text
LANGUAGE plpython3u SECURITY DEFINER SET search_path = pg_catalog AS $$
held = GD.get("standard_subject")
if not held or held[0] != plpy.execute("SELECT txid_current() AS x")[0]["x"]:
    return None                                   # another transaction, or never stated: no subject, no row
return held[1]
$$;

CREATE FUNCTION standard.current_tenant() RETURNS text
LANGUAGE plpython3u SECURITY DEFINER SET search_path = pg_catalog AS $$
held = GD.get("standard_subject")
if not held or held[0] != plpy.execute("SELECT txid_current() AS x")[0]["x"]:
    return None
return held[2]
$$;

REVOKE ALL ON FUNCTION standard.act_as(text), standard.current_subject(), standard.current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION standard.act_as(text), standard.current_subject(), standard.current_tenant() TO product;

CREATE FUNCTION standard.protect() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    obj record;
    seq record;
    has_owner boolean;
    has_tenant boolean;
BEGIN
    FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() WHERE command_tag = 'CREATE TABLE' LOOP
        SELECT bool_or(attname = 'owner_id'), bool_or(attname = 'tenant_id') INTO has_owner, has_tenant
        FROM pg_attribute WHERE attrelid = obj.objid AND attnum > 0 AND NOT attisdropped;
        IF has_owner OR has_tenant THEN
            EXECUTE format('ALTER TABLE %s OWNER TO standard_owner', obj.object_identity);
            EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', obj.object_identity);
            EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', obj.object_identity);
            IF has_owner THEN
                EXECUTE format('CREATE POLICY standard_owner ON %s AS RESTRICTIVE USING (owner_id::text = standard.current_subject()) '
                               'WITH CHECK (owner_id::text = standard.current_subject())', obj.object_identity);
            END IF;
            IF has_tenant THEN
                EXECUTE format('CREATE POLICY standard_tenant ON %s AS RESTRICTIVE USING (tenant_id::text = standard.current_tenant()) '
                               'WITH CHECK (tenant_id::text = standard.current_tenant())', obj.object_identity);
            END IF;
            EXECUTE format('CREATE POLICY standard_rows ON %s USING (true) WITH CHECK (true)', obj.object_identity);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO product', obj.object_identity);
            FOR seq IN SELECT d.objid::regclass AS name FROM pg_depend d JOIN pg_class s ON s.oid = d.objid
                       WHERE d.refobjid = obj.objid AND s.relkind = 'S' LOOP
                EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO product', seq.name);
            END LOOP;
        END IF;
    END LOOP;
END;
$$;
CREATE EVENT TRIGGER standard_protect ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION standard.protect();
"""


def _as_postgres() -> list:
    """initdb and postgres refuse root: as root, they run as the system's postgres user."""
    return ["runuser", "-u", "postgres", "--"] if os.getuid() == 0 else []


class Database:
    def __init__(self, state):
        self.root = Path(state) / "pg"
        self.data, self.socket = self.root / "data", self.root / "socket"
        self.process = None

    def _chown(self, path: Path) -> None:
        if os.getuid() == 0:
            pw = pwd.getpwnam("postgres")
            os.chown(path, pw.pw_uid, pw.pw_gid)

    def psql(self, sql: str, *, user: str = "postgres", database: str = "postgres", check: bool = True) -> str:
        done = subprocess.run([*(_as_postgres() if user == "postgres" else []), str(PG / "psql"), "-X", "-q", "-A",
                               "-t", "-v", "ON_ERROR_STOP=1", "-h", str(self.socket), "-U", user, "-d", database,
                               "-c", sql], capture_output=True, text=True, timeout=60)
        if check and done.returncode != 0:
            raise RuntimeError(done.stderr.strip()[-500:])
        return done.stdout.strip() if done.returncode == 0 else done.stderr.strip()

    def start(self, *, audience: str, public_pem: str) -> "Database":
        if not (PG / "postgres").exists():
            raise RuntimeError("PostgreSQL 16 with PL/Python is needed for the data wall")
        self.root.parent.chmod(self.root.parent.stat().st_mode | 0o111)    # postgres may traverse, not list
        for path in (self.root, self.socket):
            path.mkdir(parents=True, exist_ok=True)
            self._chown(path)
        self.socket.chmod(0o755)
        subprocess.run([*_as_postgres(), str(PG / "initdb"), "-D", str(self.data), "-A", "reject", "-U", "postgres"],
                       check=True, capture_output=True, timeout=120)
        hba = self.data / "pg_hba.conf"
        # Only this socket exists (no TCP): the platform as postgres, the product as itself, nothing else.
        hba.write_text("local all postgres peer\nlocal product product trust\nlocal all all reject\n")
        self._chown(hba)
        self.process = subprocess.Popen([*_as_postgres(), str(PG / "postgres"), "-D", str(self.data),
                                         "-c", f"unix_socket_directories={self.socket}", "-c", "listen_addresses=",
                                         "-c", "unix_socket_permissions=0777"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if subprocess.run([str(PG / "pg_isready"), "-h", str(self.socket)], capture_output=True).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("PostgreSQL did not start")
        for statement in SETUP.strip().split(";\n"):
            if statement.strip():
                self.psql(statement)
        self.psql("CREATE EXTENSION IF NOT EXISTS plpython3u", database="product")
        self.psql(SCHEMA, database="product")
        self.psql(f"INSERT INTO standard.identity_key VALUES ('{audience}', $pem${public_pem}$pem$)", database="product")
        return self

    def bac_env(self, socket_in_bac: str) -> dict:
        return {"PGHOST": socket_in_bac, "PGUSER": "product", "PGDATABASE": "product",
                "DATABASE_URL": f"postgresql://product@/product?host={socket_in_bac}"}

    def stop(self) -> None:
        if self.process:
            subprocess.run([*_as_postgres(), str(PG / "pg_ctl"), "-D", str(self.data), "stop", "-m", "fast"],
                           capture_output=True, timeout=60)
            self.process.wait(timeout=30)
        shutil.rmtree(self.root, ignore_errors=True)
