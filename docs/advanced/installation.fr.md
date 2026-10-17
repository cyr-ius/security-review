# Installation : autres cas

L'installation courante est décrite dans [Installation](../getting-started/installation.md).
Cette page couvre l'installation depuis les sources et sans accès Internet.

## Depuis les sources

```bash
git clone https://github.com/cyr-ius/security-review-mcp.git
cd security-review-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # ajouter ".[postgres]" pour PostgreSQL
cp .env.example .env
pytest && ruff check .
```

L'[interface web](../usage/web-interface.md) est une application Angular à compiler
(Node.js 22.22.3+ ou 24.15+, requis par Angular 22) ; sans elle, le contrôleur ne sert que l'API REST :

```bash
cd web && npm ci && npm run build   # écrit dans src/security_review_mcp/webui/
```

## Installation hors ligne

Pour un environnement sans accès Internet, préparez les wheels sur une machine connectée,
avec **la même version de Python que la cible** (ici 3.14) :

```bash
(cd web && npm ci && npm run build)   # interface web, embarquée dans la wheel
python3.14 -m pip wheel --no-deps -w wheels .
python3.14 -m pip download -d wheels "mcp>=2,<3" "sqlmodel>=0.0.22" "pydantic-settings>=2.2" \
    "fastapi>=0.135" "tomlkit>=0.13" "alembic>=1.13"
# PostgreSQL uniquement : python3.14 -m pip download -d wheels psycopg2-binary
```

Copiez ensuite le dossier `wheels/` sur la machine cible.

!!! note "Même plateforme"
    La machine cible doit avoir le même OS et la même architecture que la machine connectée.
    Sinon, ajoutez `--platform` et `--only-binary=:all:` à `pip download`.

Puis, sur la machine cible, en ciblant explicitement Python 3.14 :

```bash
python3.14 -m venv /opt/security-review-mcp/venv
/opt/security-review-mcp/venv/bin/pip install --no-index --find-links wheels security-review-mcp
```
