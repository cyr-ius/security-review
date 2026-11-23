"""Type aliases shared by the schemas."""

from typing import Literal

AuthSource = Literal["local", "oidc"]
Origin = Literal["builtin", "custom"]
Granularity = Literal["day", "week", "month"]
