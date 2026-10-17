"""SQLite architecture map: descriptive, versioned by Git, never an authority source.

Run ``python -m interface.context.cartography overview`` from the repository root.
The database is opened read-only unless ``init`` or ``import-json`` is requested.
"""
from __future__ import annotations

import argparse
import hashlib
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
DETAILS = """
CREATE TABLE link_conditions (
  source_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  timing TEXT NOT NULL CHECK(length(timing) BETWEEN 1 AND 500),
  checks TEXT NOT NULL CHECK(length(checks) BETWEEN 1 AND 1500),
  on_failure TEXT NOT NULL CHECK(length(on_failure) BETWEEN 1 AND 1000),
  scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 1000),
  limitation TEXT NOT NULL CHECK(length(limitation) BETWEEN 1 AND 1500),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 300),
  PRIMARY KEY(source_id,kind,target_id),
  FOREIGN KEY(source_id,kind,target_id) REFERENCES links(source_id,kind,target_id) ON DELETE CASCADE
);
CREATE TABLE flows (
  id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 2 AND 100),
  title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
  description TEXT NOT NULL CHECK(length(description) BETWEEN 1 AND 2000),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 300)
);
CREATE TABLE flow_steps (
  flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK(position BETWEEN 1 AND 64),
  source_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  PRIMARY KEY(flow_id,position),
  FOREIGN KEY(source_id,kind,target_id) REFERENCES links(source_id,kind,target_id) ON DELETE CASCADE
);
"""
FINGERPRINTS = """
CREATE TABLE source_fingerprints (
  source TEXT PRIMARY KEY CHECK(length(source) BETWEEN 1 AND 300),
  sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*')
);
"""
DEPENDENCIES = ('runs_in', 'uses_identity', 'administered_by', 'uses_secret',
                'shares_budget', 'uses_kernel', 'loads_from', 'stores_in', 'inherits_account_of')
CONTROL_LINKS = ('governed_by', 'mediated_by', 'limited_by')
TOPOLOGY_LINKS = (*DEPENDENCIES, 'contains', 'instance_of', 'outside_of', 'spawned_by',
                  'mounts_ro', 'mounts_rw', 'excludes_mount', 'listens_on', 'connects_to',
                  'serves', 'transfers_to', 'can_read', 'can_write', 'holds', 'launches',
                  'protects_access', 'measures_property', 'exercises_access', 'checks_property',
                  'uses_environment', 'targets_environment', 'has_role', 'coverage_limit', 'expects_property', 'uses_probe')

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
""" + ASSESSMENTS + DETAILS + FINGERPRINTS + "INSERT INTO metadata VALUES('schema_version','4');"


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


def _has_table(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _source_tables(db: sqlite3.Connection) -> list[str]:
    return [name for name in ('nodes', 'links', 'expectations', 'assessments', 'link_conditions', 'flows')
            if _has_table(db, name)]


def source_paths(db: sqlite3.Connection) -> set[str]:
    return {row[0].split('#', 1)[0] for table in _source_tables(db)
            for row in db.execute(f'SELECT DISTINCT source FROM {table}')}


def fingerprint_sources(db: sqlite3.Connection, root: Path = ROOT) -> None:
    """Explicit byte baseline for drift detection, never a semantic review or test result."""
    errors = validate(db, root)
    if errors:
        raise ValueError('; '.join(errors))
    rows = [(source, hashlib.sha256((root / source).read_bytes()).hexdigest())
            for source in sorted(source_paths(db))]
    db.execute('DELETE FROM source_fingerprints')
    db.executemany('INSERT INTO source_fingerprints VALUES (?,?)', rows)


def source_drift(db: sqlite3.Connection, root: Path = ROOT) -> dict:
    recorded = ({r['source']: r['sha256'] for r in _rows(db, 'SELECT * FROM source_fingerprints')}
                if _has_table(db, 'source_fingerprints') else {})
    current = source_paths(db)
    changed, unavailable = [], []
    checkout = root.resolve()
    for source in sorted(current & recorded.keys()):
        path = (checkout / source).resolve()
        if (Path(source).is_absolute() or '..' in Path(source).parts or
                not path.is_relative_to(checkout) or not path.is_file()):
            unavailable.append(source)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != recorded[source]:
            changed.append(source)
    return {'changed': changed, 'unavailable': unavailable, 'not_recorded': sorted(current - recorded.keys()),
            'no_longer_referenced': sorted(recorded.keys() - current),
            'meaning': 'Différence des octets source depuis la photographie de la carte ; absence de dérive ne prouve pas justesse sémantique.'}


def audit(db: sqlite3.Connection, root: Path = ROOT) -> dict:
    errors = validate(db, root)
    if errors:
        return {'structural_errors': errors, 'inventory_complete': False}
    inventory = coverage(db, root, limit=200)
    isolated = [r[0] for r in db.execute("""SELECT id FROM nodes n WHERE NOT EXISTS
        (SELECT 1 FROM links l WHERE l.source_id=n.id OR l.target_id=n.id) ORDER BY id""")]
    source_ownerless = [r[0] for r in db.execute("""SELECT id FROM nodes n WHERE id LIKE 'component/enforcer/%'
        AND NOT EXISTS (SELECT 1 FROM links l WHERE l.source_id=n.id AND l.kind='implements') ORDER BY id""")]
    adjacency = {r[0]: set() for r in db.execute('SELECT id FROM nodes')}
    for a, b in db.execute('SELECT source_id,target_id FROM links'):
        adjacency[a].add(b)
        adjacency[b].add(a)
    seen = {r[0] for r in db.execute("SELECT id FROM nodes WHERE kind='domain'")}
    queue = deque(seen)
    while queue:
        for other in adjacency[queue.popleft()] - seen:
            seen.add(other)
            queue.append(other)
    unreachable = sorted(adjacency.keys() - seen)
    oversized = []
    for id in sorted(adjacency):
        try:
            context(db, id)
        except ValueError as exc:
            oversized.append({'id': id, 'packet': 'context', 'error': str(exc)})
    if _has_table(db, 'flows'):
        for (id,) in db.execute('SELECT id FROM flows ORDER BY id'):
            try:
                flow(db, id)
            except ValueError as exc:
                oversized.append({'id': id, 'packet': 'flow', 'error': str(exc)})
    drift = source_drift(db, root)
    documentary_gaps = gaps(db)
    counts = {category: sum(x['category'] == category for x in documentary_gaps)
              for category in ('architecture', 'missing_link', 'missing_condition')}
    return {'structural_errors': [], 'coverage': inventory, 'isolated_nodes': isolated,
            'unreachable_from_domains': unreachable, 'source_nodes_without_owner': source_ownerless,
            'oversized_packets': oversized, 'source_drift': drift, 'gap_counts': counts,
            'inventory_complete': not (inventory['unreferenced'] or isolated or source_ownerless or unreachable or
                                       oversized or counts['missing_condition'] or drift['changed'] or drift['unavailable'] or drift['not_recorded'] or drift['no_longer_referenced']),
            'semantic_completeness': 'not_proven', 'deployment_qualification': 'not_assessed',
            'meaning': 'Complétude de l’inventaire selon le périmètre coverage, navigation non orientée et fraîcheur des sources seulement. Les lacunes ne sont pas supprimées ; ni tous les comportements ni tous les accès ne sont démontrés.'}


def conditions(db: sqlite3.Connection, source_id: str, kind: str, target_id: str) -> dict | None:
    if not _has_table(db, 'link_conditions'):
        return None
    row = db.execute('SELECT * FROM link_conditions WHERE source_id=? AND kind=? AND target_id=?',
                     (source_id, kind, target_id)).fetchone()
    return dict(row) if row else None


def _bounded(packet: dict) -> dict:
    if len(json.dumps(packet, ensure_ascii=False)) > MAX_CONTEXT_CHARS:
        raise ValueError('context exceeds 28000 characters; use node --depth 0, search or shared --limit to narrow the question')
    return packet


def flow(db: sqlite3.Connection, key: str) -> dict:
    row = db.execute('SELECT * FROM flows WHERE id=?', (key,)).fetchone() if _has_table(db, 'flows') else None
    if row is None:
        raise ValueError(f'unknown flow: {key}')
    steps = _rows(db, """SELECT s.position,l.* FROM flow_steps s JOIN links l
        USING(source_id,kind,target_id) WHERE s.flow_id=? ORDER BY s.position""", (key,))
    for step in steps:
        step['conditions'] = conditions(db, step['source_id'], step['kind'], step['target_id'])
    ids = sorted({s[k] for s in steps for k in ('source_id', 'target_id')})
    return _bounded({'flow': dict(row), 'steps': steps,
                     'basis': {r['key']: r['value'] for r in _rows(db, 'SELECT * FROM metadata')},
                     'nodes': [dict(db.execute('SELECT * FROM nodes WHERE id=?', (id,)).fetchone()) for id in ids],
                     'meaning': 'Parcours décrit dans le code, pas trace exécutée. Conditions absentes = non renseignées. Lire context ID pour les dépendances et inconnues.'})


def shared(db: sqlite3.Connection, key: str, *, limit: int, offset: int) -> dict:
    if db.execute('SELECT 1 FROM nodes WHERE id=?', (key,)).fetchone() is None:
        raise ValueError(f'unknown node: {key}')
    marks = ','.join('?' for _ in DEPENDENCIES)
    dependencies = _rows(db, f'SELECT * FROM links WHERE source_id=? AND kind IN ({marks}) ORDER BY target_id,kind',
                         (key, *DEPENDENCIES))
    items = []
    for dependency in sorted({r['target_id'] for r in dependencies}):
        items.extend(_rows(db, f"""SELECT target_id AS dependency_id,source_id AS node_id,kind,description,source
            FROM links WHERE target_id=? AND source_id<>? AND kind IN ({marks}) ORDER BY source_id,kind""",
                           (dependency, key, *DEPENDENCIES)))
    return _bounded({'focus': key, 'dependencies': dependencies, 'items': items[offset:offset + limit],
            'next_offset': offset + limit if len(items) > offset + limit else None,
            'meaning': 'Dépendances directes communes documentées ; lire leurs conditions. Assemblage local ou optionnel, pas inventaire observé du déploiement. Absence de lien ne prouve pas indépendance.'})


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
    sources = source_paths(db)
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
             'conditions': [detail for link in graph['links']
                            if (detail := conditions(db, link['source_id'], link['kind'], link['target_id'])) is not None],
             'missing_conditions': [{k: l[k] for k in ('source_id', 'kind', 'target_id', 'source')}
                                    for l in graph['links'] if l['source_id'] == key and l['kind'] in CONTROL_LINKS
                                    and conditions(db, l['source_id'], l['kind'], l['target_id']) is None],
             'dependency_ids': sorted({l['target_id'] for l in graph['links']
                                       if l['source_id'] == key and l['kind'] in DEPENDENCIES}),
             'flow_ids': [r[0] for r in db.execute('SELECT DISTINCT flow_id FROM flow_steps WHERE source_id=? OR target_id=? ORDER BY flow_id', (key, key))]
                         if _has_table(db, 'flow_steps') else [],
             'question_ids': [node['id'] for node in nodes.values() if node['kind'] == 'gap'],
             'missing_links': _rows(db, 'SELECT * FROM missing_links WHERE node_id=?', (key,))}
    return _bounded(packet)


def gaps(db: sqlite3.Connection) -> list[dict]:
    explicit = _rows(db, """SELECT id, title, description, state, source, 'architecture' AS category
        FROM nodes WHERE kind='gap' ORDER BY id""")
    missing = _rows(db, """SELECT node_id AS id, link_kind, direction, target_kind,
        reason AS description, source, 'missing_link' AS category FROM missing_links
        ORDER BY node_id, link_kind""")
    undocumented = []
    for link in _rows(db, "SELECT l.* FROM links l JOIN nodes n ON n.id=l.source_id WHERE n.kind='capability' ORDER BY l.source_id,l.kind,l.target_id"):
        if link['kind'] in CONTROL_LINKS and conditions(db, link['source_id'], link['kind'], link['target_id']) is None:
            undocumented.append({'id': link['source_id'], 'link_kind': link['kind'], 'target_id': link['target_id'],
                                 'description': 'Moment, vérifications, échec et périmètre du contrôle non renseignés.',
                                 'source': link['source'], 'category': 'missing_condition'})
    return explicit + missing + undocumented


def neighborhood(db: sqlite3.Connection, node_id: str, depth: int = 1, *, kinds: tuple | None = None) -> dict:
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
            filter_sql = f" AND kind IN ({','.join('?' for _ in kinds)})" if kinds else ''
            for row in _rows(db, "SELECT * FROM links WHERE (source_id=? OR target_id=?)" + filter_sql +
                             " ORDER BY source_id,kind,target_id", (current, current, *(kinds or ()))):
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
    required = {'metadata': ('key', 'value'),
                'nodes': ('id', 'kind', 'title', 'description', 'state', 'source'),
                'links': ('source_id', 'kind', 'target_id', 'description', 'source'),
                'expectations': ('node_id', 'link_kind', 'direction', 'target_kind', 'reason', 'source'),
                'missing_links': ('node_id', 'link_kind', 'direction', 'target_kind', 'reason', 'source')}
    for name, columns in required.items():
        actual = {row['name'] for row in db.execute(f'PRAGMA table_info({name})')}
        if not set(columns) <= actual:
            errors.append(f'required map structure missing or incomplete: {name}')
    if errors:
        return errors
    errors.extend(f"foreign key violation: {tuple(row)}" for row in db.execute("PRAGMA foreign_key_check"))
    checkout = root.resolve()
    for table in _source_tables(db):
        for (source,) in db.execute(f"SELECT DISTINCT source FROM {table}"):
            file = source.split("#", 1)[0]
            candidate = (checkout / file).resolve()
            if (Path(file).is_absolute() or ".." in Path(file).parts or
                    not candidate.is_relative_to(checkout) or not candidate.is_file()):
                errors.append(f"source absent or outside checkout: {source}")
    if _has_table(db, 'flows'):
        for (id,) in db.execute('SELECT id FROM flows ORDER BY id'):
            steps = _rows(db, 'SELECT * FROM flow_steps WHERE flow_id=? ORDER BY position', (id,))
            if not steps or [s['position'] for s in steps] != list(range(1, len(steps) + 1)):
                errors.append(f'flow positions missing or non-contiguous: {id}')
            if any(a['target_id'] != b['source_id'] for a, b in zip(steps, steps[1:])):
                errors.append(f'flow has disconnected steps: {id}')
    basis = db.execute("SELECT value FROM metadata WHERE key='basis_sha'").fetchone()
    if not basis or len(basis[0]) != 40 or any(c not in '0123456789abcdef' for c in basis[0]):
        errors.append("basis_sha missing or invalid")
    return errors


def compare(before: sqlite3.Connection, after: sqlite3.Connection) -> dict:
    """Diff by stable identifiers; a Git revision is represented by its own DB file."""
    keys = {"metadata": ("key",), "nodes": ("id",), "links": ("source_id", "kind", "target_id"),
            "assessments": ("node_id", "dimension"),
            "link_conditions": ("source_id", "kind", "target_id"), "flows": ("id",),
            "flow_steps": ("flow_id", "position"), "source_fingerprints": ("source",),
            "expectations": ("node_id", "link_kind", "direction", "target_kind")}
    result = {}
    for table, columns in keys.items():
        def indexed(db):
            if not _has_table(db, table):
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
    if command == 'audit':
        return audit(db)
    if command == "overview":
        return {"basis": {row['key']: row['value'] for row in _rows(db, "SELECT * FROM metadata")},
                "flows": _rows(db, 'SELECT * FROM flows ORDER BY id') if _has_table(db, 'flows') else [],
                "entrypoints": _rows(db, '''SELECT DISTINCT n.id,n.title FROM links l
                    JOIN nodes n ON n.id=l.target_id WHERE l.kind='entrypoint' ORDER BY n.id'''),
                "domains": _rows(db, "SELECT id,title,description FROM nodes WHERE kind='domain' ORDER BY id"),
                "counts": {row['kind']: row['n'] for row in _rows(db, "SELECT kind,count(*) AS n FROM nodes GROUP BY kind")},
                "gaps": gaps(db)}
    if command == 'topology':
        graph = neighborhood(db, key, depth, kinds=TOPOLOGY_LINKS)
        graph['basis'] = {r['key']: r['value'] for r in _rows(db, 'SELECT * FROM metadata')}
        graph['conditions'] = [detail for link in graph['links']
                               if (detail := conditions(db, link['source_id'], link['kind'], link['target_id'])) is not None]
        graph['focus'] = key
        graph['meaning'] = ('Topologie décrite dans le code : laboratoire, Stack optionnelle et fixtures de mesure sont distincts. '
                            'Aucun déploiement observé ni résultat de sonde enregistré. Exclut les liens de simple citation ; '
                            'lire context ID pour les questions et appréciations. La profondeur est bornée, pas la liste de tous les accès possibles.')
        return _bounded(graph)
    if command == 'flow':
        return flow(db, key)
    if command == 'shared':
        return shared(db, key, limit=limit, offset=offset)
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
               "expectations": ("node_id", "link_kind", "direction", "target_kind", "reason", "source"),
               "link_conditions": ("source_id", "kind", "target_id", "timing", "checks", "on_failure", "scope", "limitation", "source"),
               "flows": ("id", "title", "description", "source"),
               "flow_steps": ("flow_id", "position", "source_id", "kind", "target_id"),
               "source_fingerprints": ("source", "sha256")}
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
    p.add_argument("command", choices=("init", "import-json", "overview", "gaps", "search", "node", "path", "validate", "compare", "context", "coverage", "flow", "shared", "topology", "audit"))
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
    if args.json or args.command in ('context', 'flow', 'shared', 'topology', 'audit'):
        print(json.dumps(result, ensure_ascii=False, indent=None if args.command in ('context', 'flow', 'shared', 'topology', 'audit') else 2))
    else:
        if args.command == "overview":
            print("STANDARD — carte descriptive (aucune autorité)\n")
            for domain in result['domains']:
                print(f"{domain['id']}: {domain['title']} — {domain['description']}")
            print('\nEntrées de recherche : ' + ', '.join(node['id'] for node in result['entrypoints']))
            print('Parcours : ' + ', '.join(row['id'] for row in result['flows']))
            print(f"\n{len(result['gaps'])} lacunes/questions · base {result['basis'].get('basis_sha', '?')[:12]}")
            print("Commandes : context ID, topology ID, flow ID, shared ID, audit, coverage, gaps, search MOT, node ID, path SOURCE DEST, validate")
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
                             "link_conditions": ("source_id", "kind", "target_id"), "flows": ("id",),
                             "flow_steps": ("flow_id", "position"), "source_fingerprints": ("source",),
                             "expectations": ("node_id", "link_kind", "direction", "target_kind")}[table]))
        else:
            for item in result.get('items', []):
                print(f"{item['id']} [{item['kind']}/{item['state']}] {item['title']}")
            if result.get('next_offset') is not None:
                print(f"Suite disponible : --offset {result['next_offset']}")
    if (args.command == 'validate' and result['errors']) or (args.command == 'audit' and not result['inventory_complete']):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
