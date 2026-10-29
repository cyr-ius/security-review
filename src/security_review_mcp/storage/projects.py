"""Known projects (``Project``): the registry every part of the database refers to.

A project becomes known through its first report (reports.services.save_report, from the MCP
server or the pipeline), a token that reaches it (auth.token_store), a creation or an approval
in the web interface (auth.access_control). The name must already be normalized
(project_names.normalize_project). This module imports nothing from the controller: the MCP
server uses it.
"""

from sqlalchemy.dialects import postgresql, sqlite
from sqlmodel import Session, select

from .models import Project, utcnow


def project_exists(session: Session, name: str) -> bool:
    """True when the (normalized) project ``name`` is known."""
    return session.exec(select(Project.id).where(Project.name == name)).first() is not None


def known_projects(session: Session) -> set[str]:
    """Names of every known project."""
    return set(session.exec(select(Project.name)).all())


def ensure_project(session: Session, name: str, created_by: str | None = None) -> Project:
    """Return the project ``name`` (normalized), created when missing.

    Two requests that create the same project at the same time both get it: the second insert
    does nothing.
    """
    row = session.exec(select(Project).where(Project.name == name)).first()
    if row is not None:
        return row
    actor = created_by[:200] if created_by else None
    dialect = session.get_bind().dialect.name
    if dialect in ("postgresql", "sqlite"):
        insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
        session.execute(
            insert(Project.__table__)  # type: ignore[attr-defined]
            .values(name=name, autojoin_blocked=False, created_by=actor, created_at=utcnow())
            .on_conflict_do_nothing(index_elements=["name"])
        )
    else:
        session.add(Project(name=name, created_by=actor))
        session.flush()
    return session.exec(select(Project).where(Project.name == name)).one()
