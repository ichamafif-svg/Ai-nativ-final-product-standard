-- Descriptive map only. The graph is not a security authority or an evidence store.
-- Apply as the owner of a dedicated cartography database, not as the product role.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA cartography;
REVOKE ALL ON SCHEMA cartography FROM PUBLIC;

CREATE TABLE cartography.revisions (
    scope text NOT NULL,
    revision text NOT NULL,
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'sealed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, revision),
    CHECK (length(scope) BETWEEN 1 AND 256 AND length(revision) BETWEEN 1 AND 256)
);

CREATE TABLE cartography.types (
    id text NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    kind text NOT NULL CHECK (kind IN ('object', 'relation')),
    label text NOT NULL,
    description text,
    properties_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, version),
    UNIQUE (id, version, kind),
    CHECK (jsonb_typeof(properties_schema) = 'object'),
    CHECK (octet_length(id) <= 128 AND octet_length(label) <= 256 AND
           octet_length(coalesce(description, '')) <= 2048 AND
           octet_length(properties_schema::text) <= 4096)
);

CREATE TABLE cartography.objects (
    scope text NOT NULL,
    revision text NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    type_id text NOT NULL,
    type_version integer NOT NULL,
    type_kind text NOT NULL DEFAULT 'object' CHECK (type_kind = 'object'),
    slug text NOT NULL,
    name text NOT NULL,
    description text,
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    knowledge_status text NOT NULL DEFAULT 'declared'
        CHECK (knowledge_status IN ('declared', 'inferred', 'corroborated', 'unknown')),
    PRIMARY KEY (scope, revision, id),
    UNIQUE (scope, revision, slug),
    FOREIGN KEY (scope, revision) REFERENCES cartography.revisions(scope, revision),
    FOREIGN KEY (type_id, type_version, type_kind) REFERENCES cartography.types(id, version, kind),
    CHECK (jsonb_typeof(properties) = 'object'),
    CHECK (octet_length(slug) <= 256 AND octet_length(name) <= 256 AND
           octet_length(coalesce(description, '')) <= 2048 AND
           octet_length(properties::text) <= 4096)
);

CREATE TABLE cartography.relations (
    scope text NOT NULL,
    revision text NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    type_id text NOT NULL,
    type_version integer NOT NULL,
    type_kind text NOT NULL DEFAULT 'relation' CHECK (type_kind = 'relation'),
    source_id uuid NOT NULL,
    target_id uuid NOT NULL,
    description text,
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    knowledge_status text NOT NULL DEFAULT 'declared'
        CHECK (knowledge_status IN ('declared', 'inferred', 'corroborated', 'unknown')),
    PRIMARY KEY (scope, revision, id),
    FOREIGN KEY (scope, revision) REFERENCES cartography.revisions(scope, revision),
    FOREIGN KEY (type_id, type_version, type_kind) REFERENCES cartography.types(id, version, kind),
    FOREIGN KEY (scope, revision, source_id) REFERENCES cartography.objects(scope, revision, id),
    FOREIGN KEY (scope, revision, target_id) REFERENCES cartography.objects(scope, revision, id),
    CHECK (jsonb_typeof(properties) = 'object'),
    CHECK (octet_length(coalesce(description, '')) <= 2048 AND
           octet_length(properties::text) <= 4096)
);
CREATE INDEX relations_from ON cartography.relations(scope, revision, source_id, type_id, type_version);
CREATE INDEX relations_to ON cartography.relations(scope, revision, target_id, type_id, type_version);

CREATE TABLE cartography.sources (
    scope text NOT NULL,
    revision text NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    object_id uuid,
    relation_id uuid,
    source_kind text NOT NULL,
    source_uri text NOT NULL,
    source_revision text,
    observed_at timestamptz,
    description text,
    PRIMARY KEY (scope, revision, id),
    FOREIGN KEY (scope, revision, object_id) REFERENCES cartography.objects(scope, revision, id),
    FOREIGN KEY (scope, revision, relation_id) REFERENCES cartography.relations(scope, revision, id),
    CHECK ((object_id IS NULL) <> (relation_id IS NULL)),
    CHECK (octet_length(source_kind) <= 128 AND octet_length(source_uri) <= 2048 AND
           octet_length(coalesce(source_revision, '')) <= 256 AND
           octet_length(coalesce(description, '')) <= 2048)
);
CREATE INDEX sources_for_object ON cartography.sources(scope, revision, object_id) WHERE object_id IS NOT NULL;
CREATE INDEX sources_for_relation ON cartography.sources(scope, revision, relation_id) WHERE relation_id IS NOT NULL;

CREATE TABLE cartography.expectations (
    scope text NOT NULL,
    revision text NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    object_type text NOT NULL,
    object_version integer NOT NULL,
    object_kind text NOT NULL DEFAULT 'object' CHECK (object_kind = 'object'),
    relation_type text NOT NULL,
    relation_version integer NOT NULL,
    relation_kind text NOT NULL DEFAULT 'relation' CHECK (relation_kind = 'relation'),
    direction text NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    min_count integer NOT NULL DEFAULT 1 CHECK (min_count > 0),
    applies_to jsonb NOT NULL DEFAULT '{}'::jsonb,
    description text,
    PRIMARY KEY (scope, revision, id),
    FOREIGN KEY (scope, revision) REFERENCES cartography.revisions(scope, revision),
    FOREIGN KEY (object_type, object_version, object_kind) REFERENCES cartography.types(id, version, kind),
    FOREIGN KEY (relation_type, relation_version, relation_kind) REFERENCES cartography.types(id, version, kind),
    CHECK (jsonb_typeof(applies_to) = 'object'),
    CHECK (octet_length(applies_to::text) <= 4096 AND
           octet_length(coalesce(description, '')) <= 2048)
);

CREATE TABLE cartography.exceptions (
    scope text NOT NULL,
    revision text NOT NULL,
    object_id uuid NOT NULL,
    expectation_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('unknown', 'not_applicable')),
    reason text NOT NULL CHECK (length(btrim(reason)) > 0 AND octet_length(reason) <= 2048),
    PRIMARY KEY (scope, revision, object_id, expectation_id),
    FOREIGN KEY (scope, revision, object_id) REFERENCES cartography.objects(scope, revision, id),
    FOREIGN KEY (scope, revision, expectation_id) REFERENCES cartography.expectations(scope, revision, id)
);

-- Drafts can be edited transactionally. Sealed revisions and type definitions
-- cannot be silently rewritten; create a new revision or type version instead.
CREATE FUNCTION cartography.guard_revision() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    current_state text;
BEGIN
    IF TG_TABLE_NAME = 'revisions' THEN
        IF TG_OP <> 'INSERT' AND OLD.state = 'sealed' THEN
            RAISE EXCEPTION 'sealed cartography revision';
        END IF;
        IF TG_OP = 'UPDATE' AND (OLD.scope, OLD.revision) <> (NEW.scope, NEW.revision) THEN
            RAISE EXCEPTION 'cartography revision identity is immutable';
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            SELECT state INTO current_state FROM cartography.revisions
            WHERE scope = OLD.scope AND revision = OLD.revision FOR UPDATE;
            IF current_state = 'sealed' THEN
                RAISE EXCEPTION 'sealed cartography revision';
            END IF;
        END IF;
        IF TG_OP <> 'DELETE' THEN
            SELECT state INTO current_state FROM cartography.revisions
            WHERE scope = NEW.scope AND revision = NEW.revision FOR UPDATE;
            IF current_state = 'sealed' THEN
                RAISE EXCEPTION 'sealed cartography revision';
            END IF;
        END IF;
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
CREATE TRIGGER revisions_guard BEFORE UPDATE OR DELETE ON cartography.revisions
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_revision();
CREATE TRIGGER objects_guard BEFORE INSERT OR UPDATE OR DELETE ON cartography.objects
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_revision();
CREATE TRIGGER relations_guard BEFORE INSERT OR UPDATE OR DELETE ON cartography.relations
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_revision();
CREATE TRIGGER sources_guard BEFORE INSERT OR UPDATE OR DELETE ON cartography.sources
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_revision();
CREATE TRIGGER expectations_guard BEFORE INSERT OR UPDATE OR DELETE ON cartography.expectations
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_revision();
CREATE TRIGGER exceptions_guard BEFORE INSERT OR UPDATE OR DELETE ON cartography.exceptions
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_revision();

CREATE FUNCTION cartography.guard_type() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'cartography type definitions are immutable; add a new version';
END;
$$;
CREATE TRIGGER types_guard BEFORE UPDATE OR DELETE ON cartography.types
    FOR EACH ROW EXECUTE FUNCTION cartography.guard_type();

CREATE VIEW cartography.gaps AS
SELECT o.scope, o.revision, o.id AS object_id, o.slug, e.id AS expectation_id,
       e.relation_type, e.direction, e.min_count, actual.count AS actual_count,
       CASE WHEN actual.count >= e.min_count THEN 'documented'
            WHEN x.status IS NOT NULL THEN x.status ELSE 'missing' END AS status,
       x.reason, o.knowledge_status
FROM cartography.objects o
JOIN cartography.expectations e
  ON (o.scope, o.revision, o.type_id, o.type_version) =
     (e.scope, e.revision, e.object_type, e.object_version)
 AND o.properties @> e.applies_to
LEFT JOIN cartography.exceptions x
  ON (x.scope, x.revision, x.object_id, x.expectation_id) =
     (o.scope, o.revision, o.id, e.id)
CROSS JOIN LATERAL (
    SELECT count(*) AS count FROM cartography.relations r
    WHERE r.scope = o.scope AND r.revision = o.revision
      AND r.type_id = e.relation_type AND r.type_version = e.relation_version
      AND ((e.direction = 'outgoing' AND r.source_id = o.id)
        OR (e.direction = 'incoming' AND r.target_id = o.id))
) actual;
COMMIT;
