"""Data access (INJ-SQL, TENANT, AUTHZ object level): the ORM and bound parameters only; queries on owned models are
filtered by owner and tenant.

    rows = session.scalars(owned(select(Order), user).where(Order.id == oid))      # one statement
    db = for_user(Session(engine), user)                                         # every statement of a session

Beyond the checklists:
    - `for_user` binds a session to a user: every ORM SELECT, UPDATE and DELETE it runs gets the owner and tenant
      filters added by SQLAlchemy itself (with_loader_criteria: joins and relationship loads included), and every new
      row gets the user's owner and tenant, refusing a row that names someone else's; a query cannot forget them;
    - ownership fails closed: a model with neither an owner nor a tenant column must say it is shared
      (`__standard_shared__ = True`), otherwise reading it for a user is refused;
    - a tenant model read by a user without a tenant is refused, never returned unfiltered.
"""
from __future__ import annotations

OWNER = ("owner_id", "user_id")
TENANT = ("tenant_id", "org_id", "organization_id", "account_id")
SHARED = "__standard_shared__"


class DataRefused(ValueError):
    pass


def _columns(entity) -> tuple[str | None, str | None]:
    table = getattr(entity, "__table__", None)
    columns = {c.key for c in table.columns} if table is not None else set()
    return next((c for c in OWNER if c in columns), None), next((c for c in TENANT if c in columns), None)


def _guarded(entity) -> tuple[str | None, str | None]:
    owner, tenant = _columns(entity)
    if not owner and not tenant and not getattr(entity, SHARED, False):
        raise DataRefused(f"{getattr(entity, '__name__', entity)} has no owner or tenant column and is not "
                          f"declared shared ({SHARED} = True)")
    return owner, tenant


def owned(stmt, user):
    """A SQLAlchemy select limited to rows the user owns and to the user's tenant, for every entity it selects."""
    for desc in stmt.column_descriptions:
        entity = desc.get("entity")
        if entity is None:
            continue
        owner, tenant = _guarded(entity)
        if owner:
            stmt = stmt.where(getattr(entity, owner) == user.id)
        if tenant:
            if getattr(user, "tenant", None) is None:
                raise DataRefused("a tenant model read by a user without a tenant")
            stmt = stmt.where(getattr(entity, tenant) == user.tenant)
    return stmt


def for_user(session, user):
    """Bind an ORM session to a user: owner and tenant filters on every statement, owner and tenant on every new
    row. Returns the session. Use one session per request."""
    from sqlalchemy import event
    from sqlalchemy.orm import with_loader_criteria

    uid, tid = user.id, getattr(user, "tenant", None)

    @event.listens_for(session, "do_orm_execute")
    def _filter(state):
        if not (state.is_select or state.is_update or state.is_delete) or state.execution_options.get("standard_system"):
            return
        options = []
        for mapper in state.all_mappers:
            cls = mapper.class_
            owner, tenant = _guarded(cls)
            if tenant and tid is None:
                raise DataRefused("a tenant model read by a user without a tenant")
            if owner:
                options.append(with_loader_criteria(cls, getattr(cls, owner) == uid))
            if tenant:
                options.append(with_loader_criteria(cls, getattr(cls, tenant) == tid))
        if options:
            state.statement = state.statement.options(*options)

    @event.listens_for(session, "before_flush")
    def _stamp(sess, flush_context, instances):
        for obj in list(sess.new) + list(sess.dirty):
            owner, tenant = _columns(type(obj))
            for column, value in ((owner, uid), (tenant, tid)):
                if not column:
                    continue
                current = getattr(obj, column, None)
                if current is None and obj in sess.new:
                    if value is None:
                        raise DataRefused("a tenant row written by a user without a tenant")
                    setattr(obj, column, value)
                elif current != value:
                    raise DataRefused(f"a row of {type(obj).__name__} belongs to someone else")
    return session
