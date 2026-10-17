"""SQLite architecture map: descriptive, versioned by Git, never an authority source.

Run ``python -m interface.context.cartography overview`` from the repository root.
The database is opened read-only unless ``init`` or ``import-json`` is requested.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "interface" / "context" / "standard.sqlite"
KINDS = ("domain", "component", "authority", "agent", "capability", "constraint",
         "effect", "resource", "instrument", "guarantee", "gap", "product")
STATES = ("documented", "partial", "unknown", "missing")
MAX_CONTEXT_CHARS = 28_000
ASSESSMENTS = """
CREATE TABLE assessments (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  dimension TEXT NOT NULL CHECK(dimension IN ('implementation','deployment','verification')),
  state TEXT NOT NULL CHECK(state IN ('present','partial','absent','unknown','not_applicable')),
  note TEXT NOT NULL CHECK(length(note) BETWEEN 1 AND 1000),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 300),
  PRIMARY KEY(node_id,dimension)
);
"""
SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE nodes (
  id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 2 AND 100),
  kind TEXT NOT NULL CHECK(kind IN ('domain','component','authority','agent','capability',
    'constraint','effect','resource','instrument','guarantee','gap','product')),
  title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
  description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 2000),
  state TEXT NOT NULL DEFAULT 'documented' CHECK(state IN ('documented','partial','unknown','missing')),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 300)
);
CREATE TABLE links (
  source_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(length(kind) BETWEEN 2 AND 60),
  target_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 1000),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 300),
  PRIMARY KEY(source_id,kind,target_id)
);
CREATE INDEX links_target ON links(target_id,kind);
CREATE TABLE expectations (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  link_kind TEXT NOT NULL CHECK(length(link_kind) BETWEEN 2 AND 60),
  direction TEXT NOT NULL CHECK(direction IN ('out','in')),
  target_kind TEXT NOT NULL DEFAULT '' CHECK(target_kind IN ('','domain','component','authority',
    'agent','capability','constraint','effect','resource','instrument','guarantee','gap','product')),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 300),
  PRIMARY KEY(node_id,link_kind,direction,target_kind)
);
CREATE VIEW missing_links AS
SELECT e.node_id, e.link_kind, e.direction, e.target_kind, e.reason, e.source
FROM expectations e WHERE NOT EXISTS (
  SELECT 1 FROM links l JOIN nodes other ON other.id =
    CASE WHEN e.direction='out' THEN l.target_id ELSE l.source_id END
  WHERE l.kind=e.link_kind AND
    (CASE WHEN e.direction='out' THEN l.source_id ELSE l.target_id END)=e.node_id
    AND (e.target_kind='' OR other.kind=e.target_kind)
);
""" + ASSESSMENTS + "INSERT INTO metadata VALUES('schema_version','2');"


class MapConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(path: Path = DEFAULT_DB, *, write: bool = False) -> sqlite3.Connection:
    if write:
        db = sqlite3.connect(path, factory=MapConnection)
    else:
        db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, factory=MapConnection)
        db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA foreign_keys=ON")
    db.row_factory = sqlite3.Row
    return db


def initialize(path: Path) -> None:
    """Explicitly create a new map; never erase an existing one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path, write=True) as db:
        if db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]:
            raise ValueError("database exists; refusing to replace it")
        db.executescript(SCHEMA)


def _rows(db: sqlite3.Connection, sql: str, args: tuple = ()) -> list[dict]:
    return [dict(row) for row in db.execute(sql, args)]


def _source_tables(db: sqlite3.Connection) -> list[str]:
    tables = ['nodes', 'links', 'expectations']
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='assessments'").fetchone():
        tables.append('assessments')
    return tables


def assessments(db: sqlite3.Connection, node_id: str) -> list[dict]:
    """Missing knowledge stays unknown; a documented node is not a deployed node."""
    known = ({row['dimension']: dict(row) for row in db.execute(
        'SELECT * FROM assessments WHERE node_id=?', (node_id,))}
        if 'assessments' in _source_tables(db) else {})
    return [known.get(dimension, {'node_id': node_id, 'dimension': dimension, 'state': 'unknown',
                                 'note': 'Non renseigné dans la carte.', 'source': None})
            for dimension in ('implementation', 'deployment', 'verification')]


def coverage(db: sqlite3.Connection, root: Path = ROOT, *, limit: int = 100, offset: int = 0) -> dict:
    """Direct source references among tracked code/config files, never behavioral coverage."""
    if not 1 <= limit <= 200 or not 0 <= offset <= 1_000_000:
        raise ValueError('invalid coverage page')
    def git(*args):
        run = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=10)
        if run.returncode:
            raise ValueError('coverage requires a Git checkout')
        return run.stdout.decode('utf-8')
    suffixes = {'.py', '.sh', '.toml', '.json', '.sql', '.js', '.mjs', '.ts', '.tsx', '.yml', '.yaml',
                '.hcl', '.ini', '.cfg', '.lock', '.in', '.hashes', '.txt', '.css', '.html', '.jsx'}
    tracked = [path for path in git('ls-files', '-z').split('\0') if path]
    files = sorted(path for path in tracked if
                   (Path(path).suffix in suffixes or Path(path).name in {'Makefile', 'Dockerfile'}))
    excluded_types = {}
    included = set(files)
    for path in tracked:
        if path not in included:
            suffix = Path(path).suffix or '(no suffix)'
            excluded_types[suffix] = excluded_types.get(suffix, 0) + 1
    sources = {row[0].split('#', 1)[0] for table in _source_tables(db)
               for row in db.execute(f'SELECT DISTINCT source FROM {table}')}
    groups = {}
    for path in files:
        parts = Path(path).parts
        group = '/'.join(parts[:2]) if len(parts) > 2 else parts[0] if len(parts) > 1 else '(root)'
        counts = groups.setdefault(group, {'tracked': 0, 'referenced': 0})
        counts['tracked'] += 1
        counts['referenced'] += path in sources
    absent = [path for path in files if path not in sources]
    basis = db.execute("SELECT value FROM metadata WHERE key='basis_sha'").fetchone()
    return {'basis_sha': basis[0] if basis else None, 'checkout_sha': git('rev-parse', 'HEAD').strip(),
            'tracked': len(files), 'referenced': len(files) - len(absent), 'unreferenced': len(absent),
            'excluded_types': excluded_types,
            'groups': groups, 'items': absent[offset:offset + limit],
            'next_offset': offset + limit if len(absent) > offset + limit else None,
            'meaning': 'Références source directes seulement ; aucune couverture fonctionnelle ou de sécurité.'}


def context(db: sqlite3.Connection, key: str) -> dict:
    """One-hop work packet plus implementation references, open questions and knowledge limits."""
    graph = neighborhood(db, key)
    ids = [node['id'] for node in graph['nodes']]
    placeholders = ','.join('?' for _ in ids)
    focus = next(node for node in graph['nodes'] if node['id'] == key)
    implementation_ids = {key}
    if focus['kind'] == 'capability':
        implementation_ids.update(link['target_id'] for link in graph['links'] if link['source_id'] == key
                                  and link['kind'] in ('mediated_by', 'limited_by', 'governed_by'))
    extra = _rows(db, f'''SELECT l.* FROM links l JOIN nodes n ON n.id=l.source_id
        WHERE l.target_id IN ({placeholders}) AND (l.kind='implements' OR (l.kind='concerns' AND n.kind='gap'))
        ORDER BY l.kind,l.source_id,l.target_id''', tuple(ids))
    nodes = {node['id']: node for node in graph['nodes']}
    links = {(link['source_id'], link['kind'], link['target_id']): link for link in graph['links']}
    for link in extra:
        if link['kind'] == 'implements' and link['target_id'] not in implementation_ids:
            continue
        if focus['kind'] == 'domain' and link['kind'] == 'concerns' and link['target_id'] != key:
            continue
        links[(link['source_id'], link['kind'], link['target_id'])] = link
        if link['source_id'] not in nodes:
            nodes[link['source_id']] = dict(db.execute('SELECT * FROM nodes WHERE id=?', (link['source_id'],)).fetchone())
    for node in nodes.values():
        source = db.execute("SELECT 1 FROM links WHERE source_id=? AND kind='implements'", (node['id'],)).fetchone()
        node['representation'] = 'source' if source else 'architecture'
        node['knowledge'] = {row['dimension']: row['state'] for row in assessments(db, node['id'])}
    packet = {'nodes': [nodes[id] for id in sorted(nodes)], 'links': [links[id] for id in sorted(links)],
             'basis': {row['key']: row['value'] for row in _rows(db, 'SELECT * FROM metadata')},
             'meaning': 'state décrit la connaissance documentaire ; assessments sépare code, déploiement et vérification. Le paquet couvre un voisinage, pas tout le système.',
             'scope': ('Domaine : relations et questions directes seulement ; lire context ID pour les responsabilités voisines.'
                       if focus['kind'] == 'domain' else
                       'Relations directes et questions des voisins ; sources du focus et de ses contrôles pour une capacité. Poursuivre par context ID pour les autres voisins.'),
             'focus': key, 'assessments': assessments(db, key),
             'question_ids': [node['id'] for node in nodes.values() if node['kind'] == 'gap'],
             'missing_links': _rows(db, 'SELECT * FROM missing_links WHERE node_id=?', (key,))}
    if len(json.dumps(packet, ensure_ascii=False)) > MAX_CONTEXT_CHARS:
        raise ValueError('context exceeds 28000 characters; use node --depth 0 and search to narrow the question')
    return packet


def gaps(db: sqlite3.Connection) -> list[dict]:
    explicit = _rows(db, """SELECT id, title, description, state, source, 'architecture' AS category
        FROM nodes WHERE kind='gap' ORDER BY id""")
    missing = _rows(db, """SELECT node_id AS id, link_kind, direction, target_kind,
        reason AS description, source, 'missing_link' AS category FROM missing_links
        ORDER BY node_id, link_kind""")
    return explicit + missing


def neighborhood(db: sqlite3.Connection, node_id: str, depth: int = 1) -> dict:
    if depth < 0 or depth > 3:
        raise ValueError("depth must be between 0 and 3")
    root = db.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
    if root is None:
        raise ValueError(f"unknown node: {node_id}")
    seen = {node_id}
    frontier = {node_id}
    edges: dict[tuple[str, str, str], dict] = {}
    for _ in range(depth):
        nxt = set()
        for current in sorted(frontier):
            for row in _rows(db, """SELECT * FROM links WHERE source_id=? OR target_id=?
                                     ORDER BY source_id,kind,target_id""", (current, current)):
                edges[(row['source_id'], row['kind'], row['target_id'])] = row
                nxt.update((row['source_id'], row['target_id']))
        frontier = nxt - seen
        seen |= frontier
    nodes = [_rows(db, "SELECT * FROM nodes WHERE id=?", (key,))[0] for key in sorted(seen)]
    return {"nodes": nodes, "links": list(edges.values())}


def shortest_path(db: sqlite3.Connection, start: str, end: str, max_depth: int = 6) -> list[dict]:
    if not 1 <= max_depth <= 8:
        raise ValueError("max_depth must be between 1 and 8")
    for key in (start, end):
        if db.execute("SELECT 1 FROM nodes WHERE id=?", (key,)).fetchone() is None:
            raise ValueError(f"unknown node: {key}")
    queue = deque([(start, [])])
    seen = {start}
    while queue:
        current, path = queue.popleft()
        if current == end:
            return path
        if len(path) == max_depth:
            continue
        for link in _rows(db, "SELECT * FROM links WHERE source_id=? ORDER BY kind,target_id", (current,)):
            if link['target_id'] not in seen:
                seen.add(link['target_id'])
                queue.append((link['target_id'], path + [link]))
    return []


def validate(db: sqlite3.Connection, root: Path = ROOT) -> list[str]:
    errors = []
    if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        errors.append("SQLite integrity_check failed")
    errors.extend(f"foreign key violation: {tuple(row)}" for row in db.execute("PRAGMA foreign_key_check"))
    checkout = root.resolve()
    for table in _source_tables(db):
        for (source,) in db.execute(f"SELECT DISTINCT source FROM {table}"):
            file = source.split("#", 1)[0]
            candidate = (checkout / file).resolve()
            if (Path(file).is_absolute() or ".." in Path(file).parts or
                    not candidate.is_relative_to(checkout) or not candidate.is_file()):
                errors.append(f"source absent or outside checkout: {source}")
    basis = db.execute("SELECT value FROM metadata WHERE key='basis_sha'").fetchone()
    if not basis or len(basis[0]) != 40 or any(c not in '0123456789abcdef' for c in basis[0]):
        errors.append("basis_sha missing or invalid")
    return errors


def compare(before: sqlite3.Connection, after: sqlite3.Connection) -> dict:
    """Diff by stable identifiers; a Git revision is represented by its own DB file."""
    keys = {"metadata": ("key",), "nodes": ("id",), "links": ("source_id", "kind", "target_id"),
            "assessments": ("node_id", "dimension"),
            "expectations": ("node_id", "link_kind", "direction", "target_kind")}
    result = {}
    for table, columns in keys.items():
        def indexed(db):
            if table == 'assessments' and table not in _source_tables(db):
                return {}
            return {tuple(row[column] for column in columns): dict(row)
                    for row in db.execute(f"SELECT * FROM {table}")}
        old, new = indexed(before), indexed(after)
        result[table] = {
            "added": [new[key] for key in sorted(new.keys() - old.keys())],
            "removed": [old[key] for key in sorted(old.keys() - new.keys())],
            "changed": [{"before": old[key], "after": new[key]}
                        for key in sorted(old.keys() & new.keys()) if old[key] != new[key]],
        }
    return result


def read(command: str, db: sqlite3.Connection, *, key: str = "", other: str = "",
         depth: int = 1, limit: int = 100, offset: int = 0) -> dict:
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if offset < 0 or offset > 1_000_000:
        raise ValueError("offset must be between 0 and 1000000")
    if command == "overview":
        return {"basis": {row['key']: row['value'] for row in _rows(db, "SELECT * FROM metadata")},
                "entrypoints": _rows(db, '''SELECT DISTINCT n.id,n.title FROM links l
                    JOIN nodes n ON n.id=l.target_id WHERE l.kind='entrypoint' ORDER BY n.id'''),
                "domains": _rows(db, "SELECT id,title,description FROM nodes WHERE kind='domain' ORDER BY id"),
                "counts": {row['kind']: row['n'] for row in _rows(db, "SELECT kind,count(*) AS n FROM nodes GROUP BY kind")},
                "gaps": gaps(db)}
    if command == "gaps":
        return {"items": gaps(db)}
    if command == 'coverage':
        return coverage(db, limit=limit, offset=offset)
    if command == 'context':
        return context(db, key)
    if command == "search":
        if not key:
            raise ValueError("search term required")
        term = '%' + key.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        page = _rows(db, """SELECT * FROM nodes WHERE id LIKE ? ESCAPE '\\' OR
            title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
            ORDER BY kind,id LIMIT ? OFFSET ?""", (term, term, term, limit + 1, offset))
        return {"items": page[:limit], "next_offset": offset + limit if len(page) > limit else None}
    if command == "node":
        graph = neighborhood(db, key, depth)
        graph['missing_links'] = _rows(db, "SELECT * FROM missing_links WHERE node_id=?", (key,))
        graph['assessments'] = assessments(db, key)
        return graph
    if command == "path":
        return {"links": shortest_path(db, key, other, depth)}
    raise ValueError(f"unknown command: {command}")


def import_json(path: Path, payload: dict) -> None:
    """Transactional, explicit editor for a new or existing map (no SQL input)."""
    allowed = {"metadata": ("key", "value"), "nodes": ("id", "kind", "title", "description", "state", "source"),
               "assessments": ("node_id", "dimension", "state", "note", "source"),
               "links": ("source_id", "kind", "target_id", "description", "source"),
               "expectations": ("node_id", "link_kind", "direction", "target_kind", "reason", "source")}
    if not isinstance(payload, dict) or set(payload) - set(allowed):
        raise ValueError("unknown tables in import")
    with connect(path, write=True) as db:
        for table, columns in allowed.items():
            items = payload.get(table, [])
            if not isinstance(items, list):
                raise ValueError(f"{table} must be a list")
            for item in items:
                if not isinstance(item, dict) or set(item) - set(columns):
                    raise ValueError(f"invalid {table} item")
                names = tuple(item)
                if not names:
                    raise ValueError("empty item")
                db.execute(f"INSERT INTO {table} ({','.join(names)}) VALUES ({','.join('?' for _ in names)})",
                           tuple(item.values()))


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("init", "import-json", "overview", "gaps", "search", "node", "path", "validate", "compare", "context", "coverage"))
    p.add_argument("key", nargs="?", default="")
    p.add_argument("other", nargs="?", default="")
    p.add_argument("--db", type=Path, default=DEFAULT_DB)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.db)
            result = {"created": str(args.db)}
        elif args.command == "import-json":
            with Path(args.key).open() as f:
                import_json(args.db, json.load(f))
            result = {"imported": True}
        elif args.command == "compare":
            with connect(Path(args.key)) as before, connect(args.db) as after:
                result = compare(before, after)
        else:
            with connect(args.db) as db:
                result = ({"errors": validate(db)} if args.command == "validate" else
                          read(args.command, db, key=args.key, other=args.other,
                               depth=args.depth, limit=args.limit, offset=args.offset))
    except (ValueError, sqlite3.Error, OSError) as exc:
        p.exit(2, f"cartography: {exc}\n")
    if args.json or args.command == 'context':
        print(json.dumps(result, ensure_ascii=False, indent=None if args.command == 'context' else 2))
    else:
        if args.command == "overview":
            print("STANDARD — carte descriptive (aucune autorité)\n")
            for domain in result['domains']:
                print(f"{domain['id']}: {domain['title']} — {domain['description']}")
            print('\nEntrées de recherche : ' + ', '.join(node['id'] for node in result['entrypoints']))
            print(f"\n{len(result['gaps'])} lacunes/questions · base {result['basis'].get('basis_sha', '?')[:12]}")
            print("Commandes : context ID, coverage, gaps, search MOT, node ID, path SOURCE DEST, validate")
        elif args.command == "gaps":
            for item in result['items']:
                detail = item['description']
                if item['category'] == 'architecture':
                    print(f"[{item['category']}] {item['id']}: {item['title']}")
                    if detail and not detail.startswith('Travail restant de la garantie '):
                        print(f"  {detail}")
                else:
                    print(f"[{item['category']}] {item['id']}: {detail}")
                print(f"  source: {item['source']}")
        elif args.command == "node":
            for item in result['nodes']:
                print(f"{item['id']} [{item['kind']}/{item['state']}] {item['title']}: {item['description']}")
                print(f"  source: {item['source']}")
            for item in result['links']:
                print(f"  {item['source_id']} --{item['kind']}--> {item['target_id']} ({item['description']})")
            for item in result['missing_links']:
                print(f"  ? {item['direction']} {item['link_kind']} {item['target_kind']}: {item['reason']}")
            for item in result['assessments']:
                print(f"  {item['dimension']}={item['state']}: {item['note']}")
        elif args.command == 'coverage':
            print(result['meaning'])
            print(f"{result['referenced']}/{result['tracked']} fichiers suivis cités ; {result['unreferenced']} sans référence directe.")
            for group, counts in sorted(result['groups'].items()):
                print(f"{group}: {counts['referenced']}/{counts['tracked']} cités")
            for path in result['items']:
                print(f"? {path}")
            if result['next_offset'] is not None:
                print(f"Suite disponible : --offset {result['next_offset']}")
        elif args.command == "path":
            for item in result['links']:
                print(f"{item['source_id']} --{item['kind']}--> {item['target_id']}")
            if not result['links']:
                print("Aucun chemin dirigé documenté dans cette profondeur.")
        elif args.command == "validate":
            print("Carte valide." if not result['errors'] else '\n'.join(result['errors']))
        elif args.command == "compare":
            for table, changes in result.items():
                for action, items in changes.items():
                    for item in items:
                        row = item['after'] if action == 'changed' else item
                        print(f"{table} {action}: " + ', '.join(
                            str(row[column]) for column in
                            {"metadata": ("key",), "nodes": ("id",), "links": ("source_id", "kind", "target_id"),
                             "assessments": ("node_id", "dimension"),
                             "expectations": ("node_id", "link_kind", "direction", "target_kind")}[table]))
        else:
            for item in result.get('items', []):
                print(f"{item['id']} [{item['kind']}/{item['state']}] {item['title']}")
            if result.get('next_offset') is not None:
                print(f"Suite disponible : --offset {result['next_offset']}")
    if args.command == 'validate' and result['errors']:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
