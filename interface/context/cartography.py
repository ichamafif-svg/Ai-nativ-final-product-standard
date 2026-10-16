"""Read-only PostgreSQL cartography for humans and agents; never an authority source.

    python -m interface.context.cartography init --dbname standard_map
    python -m interface.context.cartography gaps --dbname standard_map --scope standard --revision COMMIT

psql uses libpq's ordinary connection settings (PGHOST, PGUSER, etc.). Writing is
done in SQL transactions by a separately authorized database role. No candidate
statement is ever assembled from a user-supplied SQL fragment.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

SCHEMA = Path(__file__).with_suffix(".sql")
MAX_OUTPUT = 8 << 20
PAGE_SIZE = 100

QUERIES = {
    "types": """SELECT id, version, kind, label, description, properties_schema
        FROM cartography.types ORDER BY id, version""",
    "objects": """SELECT id, slug, type_id, type_version, name, description, properties, knowledge_status
        FROM cartography.objects WHERE scope = :'scope' AND revision = :'revision' ORDER BY slug, id""",
    "relations": """SELECT r.id, r.type_id, r.type_version, s.slug AS source, d.slug AS target,
        r.description, r.properties, r.knowledge_status FROM cartography.relations r
        JOIN cartography.objects s ON (s.scope, s.revision, s.id) = (r.scope, r.revision, r.source_id)
        JOIN cartography.objects d ON (d.scope, d.revision, d.id) = (r.scope, r.revision, r.target_id)
        WHERE r.scope = :'scope' AND r.revision = :'revision'
        ORDER BY r.type_id, s.slug, d.slug, r.id""",
    "sources": """SELECT id, object_id, relation_id, source_kind, source_uri, source_revision,
        observed_at, description FROM cartography.sources
        WHERE scope = :'scope' AND revision = :'revision' ORDER BY source_uri, id""",
    "gaps": """SELECT object_id, slug, expectation_id, relation_type, direction,
        min_count, actual_count, status, reason, knowledge_status FROM cartography.gaps
        WHERE scope = :'scope' AND revision = :'revision' ORDER BY slug, relation_type, expectation_id""",
}


def run(command: str, *, dbname: str, scope: str = "", revision: str = "", offset: int = 0,
        psql: str | None = None):
    binary = psql or shutil.which("psql")
    if not binary:
        raise RuntimeError("PostgreSQL psql is required")
    args = [binary, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-w", "-d", dbname]
    if command == "init":
        # No grant is given to a product or an agent by installing the schema.
        done = subprocess.run(args + ["-f", "-"], input=SCHEMA.read_text(), text=True,
                              capture_output=True, timeout=60)
        if done.returncode:
            raise RuntimeError(done.stderr.strip()[-500:])
        return {"installed": True}
    if command not in QUERIES:
        raise ValueError("unsupported cartography query")
    if command != "types" and (not scope or not revision):
        raise ValueError("scope and revision are required")
    if type(offset) is not int or offset < 0 or offset > (1 << 63) - PAGE_SIZE or offset % PAGE_SIZE:
        raise ValueError("offset must be a non-negative multiple of 100 within PostgreSQL bigint range")
    # psql's :'name' quotes the value as an SQL literal; no caller SQL is accepted.
    query = """SELECT jsonb_build_object(
        'items', COALESCE(jsonb_agg(to_jsonb(page) - '_position' ORDER BY page._position)
                          FILTER (WHERE page._position <= :'offset'::bigint + 100), '[]'::jsonb),
        'next_offset', CASE WHEN count(*) > 100 THEN :'offset'::bigint + 100 ELSE NULL END)
        FROM (SELECT base.*, row_number() OVER () + :'offset'::bigint AS _position
              FROM (""" + QUERIES[command] + """ LIMIT 101 OFFSET :'offset'::bigint) base) page;\n"""
    with tempfile.TemporaryFile(mode="w+t") as output:
        done = subprocess.run(args + ["-v", f"scope={scope}", "-v", f"revision={revision}",
                                      "-v", f"offset={offset}", "-f", "-"], input=query,
                              text=True, stdout=output, stderr=subprocess.PIPE, timeout=20)
        if done.returncode:
            raise RuntimeError(done.stderr.strip()[-500:])
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
    if len(raw) > MAX_OUTPUT:
        raise RuntimeError("cartography response too large")
    return json.loads(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", *QUERIES))
    parser.add_argument("--dbname", required=True)
    parser.add_argument("--scope")
    parser.add_argument("--revision")
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.command, dbname=args.dbname, scope=args.scope or "",
                         revision=args.revision or "", offset=args.offset), ensure_ascii=False))


if __name__ == "__main__":
    main()
