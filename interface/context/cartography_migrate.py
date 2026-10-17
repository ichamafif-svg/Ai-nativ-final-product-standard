"""Explicit, loss-accounted v4 → v5 map migration.

Usage: python -m interface.context.cartography_migrate BEFORE.sqlite NEW.sqlite
Destination must not exist. Reads the source without altering it. Runtime readers never migrate.
The classifications below are decisions about the version-4 Standard inventory, not generic inference.
"""
import sqlite3, json, collections, hashlib
from pathlib import Path
import sys

def migration_records(old, node_types, edge_map):
    """Account for original rows, referring to each new edge by its unique identity."""
    records = []
    for node in old['nodes']:
        kept = node['id'] in node_types
        note = 'documentation=' + node['state']
        if not kept:
            removed_assessments = [row for row in old['assessments'] if row['node_id'] == node['id']]
            note = ('role replaced by typed object/method; ' + note + '; assessments=' +
                    json.dumps(removed_assessments, ensure_ascii=False))
        records.append(dict(entity='node', old_key=node['id'],
                            new_key=node['id'] if kept else None,
                            old_sha256=hashlib.sha256(json.dumps(node, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
                            note=note))
    for link in old['links']:
        key = tuple(link[field] for field in ('source_id', 'kind', 'target_id'))
        edge = edge_map.get(key)
        records.append(dict(entity='link', old_key=json.dumps(key),
                            new_key=edge[4] if edge else None,
                            old_sha256=hashlib.sha256(json.dumps(link, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
                            note=('canonical direction reversed' if edge[3] else 'normalized') if edge else
                                 'role replaced by typed object/method'))
    return records


def main():
    from interface.context.cartography import ROOT
    root = ROOT
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    before, after = args.before, args.after
    if hashlib.sha256(before.read_bytes()).hexdigest() != 'a9c295dc36f899a106ebd859345b660397792bd429ba2a68a199aab1f2064dad':
        raise ValueError('source differs from the reviewed Standard v4 snapshot; classify its changes explicitly')
    c = sqlite3.connect(f'{before.resolve().as_uri()}?mode=ro', uri=True)
    c.row_factory = sqlite3.Row
    if c.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] != '4':
        raise ValueError('migration requires a version 4 source')
    old = {t: [dict(r) for r in c.execute('select * from ' + t)] for t in ['metadata', 'nodes', 'links', 'expectations', 'assessments', 'link_conditions', 'flows', 'flow_steps', 'source_fingerprints']}
    c.close()
    roles = {r['source_id']: r['target_id'].split('role-')[-1] for r in old['links'] if r['kind'] == 'has_role'}
    removed = {r['id'] for r in old['nodes'] if r['id'].startswith('resource/role-')}

    def typ(n):
        id, k = (n['id'], n['kind'])
        s = id.split('/')[-1]
        if id.startswith('component/enforcer/') or id.startswith('instrument/tests/') or id.startswith('instrument/blocks/'):
            return 'arch/source'
        if k in ('domain', 'gap'):
            return 'arch/' + k
        if k == 'guarantee':
            return 'arch/property' if '/property-' in id else 'arch/guarantee'
        if k in ('capability', 'constraint', 'effect'):
            return 'trust/' + k
        if k == 'agent':
            return 'trust/principal'
        if k == 'authority':
            if s in ('kernel', 'bt'):
                return 'trust/judge'
            if s.endswith('owner') or s == 'host-admin':
                return 'trust/admin'
            if s == 'supervisor':
                return 'arch/component'
            return 'trust/principal'
        if k == 'instrument':
            return 'arch/component' if s == 'probes' else 'arch/probe' if roles.get(id) == 'probe' else 'arch/instrument'
        if k == 'component':
            return 'arch/component'
        if k == 'product':
            return 'arch/component'
        if id.startswith('resource/access-'):
            return 'arch/access'
        if id.startswith('resource/uid-'):
            return 'trust/account'
        if id.startswith('resource/probe-') or id.startswith('resource/test-'):
            return 'arch/fixture'
        if s.startswith('assembly-'):
            return 'arch/assembly'
        if s in ('lab-host', 'stack-host'):
            return 'run/host'
        if s == 'lab-agent-env':
            return 'run/enclosure'
        if s in ('lab-candidate-env', 'lab-verifier-env', 'product-bac'):
            return 'run/container'
        if 'process' in s:
            return 'run/process'
        if s == 'host-kernel':
            return 'run/kernel'
        if s in ('agent-budget', 'candidate-compute'):
            return 'run/cgroup'
        if s.endswith('socket'):
            return 'net/unix-socket'
        if s.endswith('port'):
            return 'net/tcp-port'
        if s in ('identity-signing-key', 'key-guard', 'key-clock', 'key-scanner', 'key-oracle'):
            return 'trust/signing-credential'
        if s == 'egress-broker-token' or s == 'product-identity-token':
            return 'trust/token'
        if s == 'secret':
            return 'trust/secret'
        if s == 'external-destination':
            return 'ext/destination'
        if s in ('lab-admission-dir', 'lab-execution-dir', 'lab-public-dir', 'lab-agent-state', 'installed-code', 'stack-egress-mount'):
            return 'fs/directory'
        if s == 'lab-private-staging':
            return 'fs/snapshot'
        if s == 'scratch':
            return 'fs/scratch'
        if s == 'lab-verification-work':
            return 'data/artifact'
        if s in ('main', 'proposals', 'inbox'):
            return 'data/repo'
        if s in ('release-tree', 'recovered-tree'):
            return 'fs/directory'
        if s == 'client-data':
            return 'data/table'
        if s == 'journal':
            return 'data/journal'
        if s == 'pins-store':
            return 'data/pin-store'
        if s in ('evidence', 'private-evidence-store'):
            return 'data/evidence-store'
        if s in ('public-captures', 'recorded-series'):
            return 'data/capture'
        if s in ('release-registers', 'traffic-live'):
            return 'data/register'
        if s in ('kernel-log', 'transaction-index'):
            return 'data/log'
        if s == 'release-artifact':
            return 'data/archive'
        if s == 'provider-adapter':
            return 'arch/component'
        if s in ('canonical-bytes', 'floor0-spec'):
            return 'arch/source'
        if s == 'python-crypto-runtime':
            return 'run/runtime'
        if s == 'clock-local':
            return 'trust/principal'
        if s in ('effective-law', 'assessment-config', 'platform-values'):
            return 'trust/policy'
        if s == 'control-identities':
            return 'trust/genesis'
        if s == 'obligations':
            return 'data/register'
        return 'data/artifact'
    nt = {n['id']: typ(n) for n in old['nodes'] if n['id'] not in removed}
    inverse = {'implemented_by': 'implements', 'launched_by': 'launches', 'spawned_by': 'launches', 'read_by': 'reads', 'polled_by': 'reads', 'verified_by': 'checked_by', 'verifies': 'checked_by', 'inspected_by': 'checked_by', 'measured_by': 'checked_by', 'observed_by': 'checked_by', 'runs_in': 'contains', 'exported_by': 'produces', 'used_by': 'depends_on'}
    inverse.pop('verified_by')
    inverse.pop('inspected_by')
    inverse.pop('measured_by')
    inverse.pop('observed_by')
    rename = {'verified_by': 'checked_by', 'inspected_by': 'checked_by', 'measured_by': 'checked_by', 'observed_by': 'checked_by', 'mounts_ro': 'mounts', 'mounts_rw': 'mounts', 'excludes_mount': 'mounts', 'can_read': 'reads', 'can_write': 'writes', 'uses_secret': 'holds', 'uses_kernel': 'confined_by', 'shares_budget': 'confined_by', 'calls': 'calls', 'connects': 'connects_to', 'forwards_to': 'connects_to', 'relays_to': 'connects_to', 'answers_to': 'responds_to', 'returns': 'responds_to', 'returns_to': 'responds_to', 'cas_result_to': 'responds_to', 'reports': 'responds_to', 'includes': 'comprises', 'coverage_limit': 'concerns', 'impacts': 'impacts', 'checks_definition': 'checked_by', 'checks_property': 'checked_by', 'measures_property': 'checked_by', 'exercises_access': 'checked_by', 'uses_fixture': 'uses_environment', 'targets_environment': 'uses_environment', 'stores': 'writes', 'updates': 'writes', 'publishes': 'writes', 'persists': 'writes', 'consults': 'depends_on', 'uses': 'depends_on', 'inherits_account_of': 'inherits_account_of'}
    rename.update({'appends_through': 'calls', 'checks_with': 'calls', 'coordinates': 'calls', 'initializes': 'calls', 'runs': 'calls', 'selects': 'calls', 'dispatches_through': 'transmits', 'dispatches_to': 'transmits', 'feeds': 'transmits', 'presented_to': 'transmits', 'reconciles_through': 'calls', 'requests_via': 'calls', 'reads_with': 'holds', 'submits_to': 'transmits', 'submitted_to': 'transmits', 'transfers_to': 'transmits', 'compiles': 'produces', 'derives': 'produces', 'drafts': 'produces', 'issues': 'produces', 'prepares': 'produces', 'reconstructs': 'produces', 'stages': 'produces', 'describes': 'documents', 'checks': 'evaluates', 'checks_purpose_of': 'evaluates', 'judges': 'evaluates', 'uses_probe': 'calls', 'constrains': 'constrains'})
    inverse.update({'filters': 'mediated_by', 'governs': 'governed_by', 'fixture_for': 'uses_environment'})
    rename['filtered_by'] = 'mediated_by'
    reverse_more = {'checks_definition', 'checks_property', 'measures_property', 'exercises_access'}

    def edge(r):
        a, k, b = (r['source_id'], r['kind'], r['target_id'])
        attrs = {}
        rev = False
        if a in removed or b in removed or k == 'has_role':
            return None
        orig = k
        if k == 'contains' and (not nt[a].startswith('run/')):
            k = 'comprises'
        elif k == 'uses_identity':
            k = 'runs_as' if nt[a] == 'run/process' else 'owned_by' if nt[a].startswith(('data/', 'trust/')) and nt[a] not in ('trust/principal', 'trust/judge') else 'uses_account'
        elif k in inverse:
            a, b = (b, a)
            k = inverse[k]
            rev = True
        elif k in reverse_more:
            a, b = (b, a)
            k = rename[k]
            rev = True
        else:
            k = rename.get(k, k)
        if k == 'contains' and (not nt[a].startswith('run/')):
            k = 'comprises'
        if orig == 'runs_in' and nt[b] in ('arch/component', 'trust/judge', 'trust/principal', 'arch/instrument', 'arch/probe'):
            k = 'hosts'
        if orig == 'implemented_by':
            k = 'realizes'
        if orig in ('uses_kernel', 'shares_budget'):
            attrs['shared'] = True
        if orig.startswith('mounts_') or orig == 'excludes_mount':
            attrs['mode'] = {'mounts_ro': 'ro', 'mounts_rw': 'rw', 'excludes_mount': 'excluded'}[orig]
        if orig == 'can_read' or orig == 'can_write':
            attrs['access'] = 'permitted'
        if orig in ('stores', 'updates', 'publishes', 'persists'):
            attrs['operation'] = orig
        if orig in ('forwards_to', 'relays_to'):
            attrs['operation'] = orig
        if orig != k:
            attrs['operation'] = orig
        if k == 'checked_by':
            checker = b
            attrs['method'] = 'simulation' if checker.endswith('topology-supervisor-contract') else 'analysis' if checker.endswith('topology-oci-config') else 'attempt' if nt[checker] == 'arch/probe' else 'unspecified'
        return (a, k, b, attrs, rev)
    mapped = collections.defaultdict(list)
    emap = {}
    for r in old['links']:
        e = edge(r)
        if e:
            key = e[:3]
            mapped[key].append((r, e[3]))
            emap[r['source_id'], r['kind'], r['target_id']] = (*key, e[4])
    links = []
    for (a, k, b), items in mapped.items():
        for r, attrs in items:
            original = (r['source_id'], r['kind'], r['target_id'])
            lid = 'edge/' + hashlib.sha256(json.dumps(original).encode()).hexdigest()[:24]
            links.append(dict(id=lid, source_id=a, kind=k, target_id=b, description=r['description'], source=r['source'], properties=json.dumps(attrs, ensure_ascii=False)))
            emap[original] = (*emap[original], lid)
    ledger = migration_records(old, nt, emap)
    from interface.context.cartography import initialize, connect, validate, fingerprint_sources
    if after.exists():
        raise ValueError('destination already exists')
    initialize(after)
    with connect(after, write=True) as db:
        for row in old['metadata']:
            if row['key'] not in ('schema_version', 'catalog_version'):
                db.execute('INSERT INTO metadata VALUES (?,?)', (row['key'], row['value']))
        db.execute("INSERT INTO metadata VALUES ('migration_from','4')")
        for n in old['nodes']:
            if n['id'] in nt:
                db.execute('INSERT INTO nodes (id,kind,title,description,knowledge_status,source) VALUES (?,?,?,?,?,?)', (n['id'], nt[n['id']], n['title'], n['description'], 'unknown' if n['state'] == 'unknown' else 'declared', n['source']))
        for l in links:
            db.execute('INSERT INTO links (id,source_id,kind,target_id,description,source,properties) VALUES (?,?,?,?,?,?,?)', tuple((l[k] for k in ('id', 'source_id', 'kind', 'target_id', 'description', 'source', 'properties'))))
        for row in old['assessments']:
            if row['node_id'] in nt:
                db.execute('INSERT INTO assessments VALUES (?,?,?,?,?)', tuple(row.values()))
        for row in old['link_conditions']:
            key = tuple((row[k] for k in ('source_id', 'kind', 'target_id')))
            e = emap[key]
            db.execute('INSERT INTO link_conditions VALUES (?,?,?,?,?,?,?,?,?,?)', (e[4], *e[:3], *(row[k] for k in ('timing', 'checks', 'on_failure', 'scope', 'limitation', 'source'))))
        for row in old['flows']:
            db.execute('INSERT INTO flows VALUES (?,?,?,?)', tuple(row.values()))
        for row in old['flow_steps']:
            e = emap[tuple((row[k] for k in ('source_id', 'kind', 'target_id')))]
            db.execute('INSERT INTO flow_steps VALUES (?,?,?,?,?,?,?)', (row['flow_id'], row['position'], *e[:3], e[4], int(e[3])))
        selectors = {'authority': 'trust/admin|trust/judge|trust/principal', 'agent': 'trust/principal', 'component': 'arch/component', 'instrument': 'arch/source|arch/instrument|arch/probe', 'constraint': 'trust/constraint', 'capability': 'trust/capability', 'effect': 'trust/effect', 'resource': 'data/*'}
        for r in old['expectations']:
            k = r['link_kind']
            d = r['direction']
            target = selectors.get(r['target_kind'], r['target_kind'])
            if k == 'runs_in':
                k = 'hosts'
                d = 'in'
                target = 'run/process'
            elif k == 'uses_identity':
                k = 'runs_as' if nt[r['node_id']] == 'run/process' else 'uses_account'
                target = 'trust/account'
            elif k == 'hosted_on':
                target = 'run/host|run/vm|run/container'
            elif k == 'accesses' or k == 'impacts':
                target = ''
            elif k == 'enforced_by':
                target = 'arch/source|arch/component'
            elif k == 'protected_by':
                target = 'trust/admin'
            elif k == 'mediated_by' and r['node_id'] == 'capability/candidate-run':
                target = 'arch/component'
            else:
                k = rename.get(k, k)
            db.execute('INSERT OR IGNORE INTO expectations VALUES (?,?,?,?,?,?)', (r['node_id'], k, d, target, r['reason'], r['source']))
        for r in ledger:
            db.execute('INSERT INTO migration_ledger VALUES (?,?,?,?,?)', tuple(r.values()))
        errors = validate(db, root)
        if errors:
            raise ValueError('\n'.join(errors))
        fingerprint_sources(db, root)
    print(f"Migrated {len(old['nodes'])} nodes to {len(nt)} typed objects; {len(old['links'])} links to {len(links)} relations. Removed only 3 role-index objects and 44 role links; recorded in migration_ledger.")
if __name__ == '__main__':
    main()
