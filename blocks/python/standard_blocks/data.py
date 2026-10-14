"""Data access (INJ-SQL, TENANT, AUTHZ object level): the ORM and bound parameters only; queries on owned models are
filtered by owner and tenant.

    rows = session.scalars(owned(select(Order), user).where(Order.id == oid))
"""
from __future__ import annotations

OWNER = ("owner_id", "user_id")
TENANT = ("tenant_id", "org_id", "organization_id", "account_id")


class DataRefused(ValueError):
    pass


def owned(stmt, user):
    """A SQLAlchemy select limited to rows the user owns and to the user's tenant, for every entity it selects that
    has an owner or tenant column. A model with neither is returned unchanged: it is not owned."""
    for desc in stmt.column_descriptions:
        entity = desc.get("entity")
        if entity is None:
            continue
        columns = {c.key for c in entity.__table__.columns}
        owner = next((c for c in OWNER if c in columns), None)
        tenant = next((c for c in TENANT if c in columns), None)
        if owner:
            stmt = stmt.where(getattr(entity, owner) == user.id)
        if tenant:
            if getattr(user, "tenant", None) is None:
                raise DataRefused("a tenant model read by a user without a tenant")
            stmt = stmt.where(getattr(entity, tenant) == user.tenant)
    return stmt
