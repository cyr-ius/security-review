"""Alembic environment: runs the migrations on the connection given by database.upgrade_db.

The package has no alembic.ini: the configuration is built in code (database.alembic_config)
and the connection is passed in ``config.attributes["connection"]``, so that the migrations
use the engine of the application (and the in-memory engine of the tests).
"""

from alembic import context
from sqlmodel import SQLModel

from security_review_mcp import models  # noqa: F401  (register the tables on the metadata)

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Run the migrations with security-review-controller db upgrade")

# render_as_batch: SQLite cannot alter most columns in place, Alembic copies the table instead
context.configure(
    connection=connection,
    target_metadata=SQLModel.metadata,
    render_as_batch=True,
    compare_type=True,
)
with context.begin_transaction():
    context.run_migrations()
