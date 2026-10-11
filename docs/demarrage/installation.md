# Installation

Python 3.11 ou plus. Le projet cible le SDK `mcp` **2.x** (`MCPServer`) ; avec un miroir interne
limité à `mcp` 1.x, l'import `mcp.server.mcpserver` ne fonctionnera pas.

## Depuis PyPI

```bash
pip install security-review-mcp
pip install "security-review-mcp[postgres]"   # avec le pilote PostgreSQL
```

## Depuis les sources

```bash
git clone https://github.com/cyr-ius/security-review-mcp.git
cd security-review-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # ajouter ".[postgres]" pour PostgreSQL
cp .env.example .env
pytest && ruff check .
```

L'[interface web](../utilisation/interface-web.md) est une application Angular à compiler
(Node.js 22.22.3+ ou 24.15+, requis par Angular 22) ; sans elle, le serveur ne sert que l'API REST :

```bash
cd web && npm ci && npm run build   # écrit dans src/security_review_mcp/webui/
```

## Installation hors ligne

Pour un environnement sans accès Internet, préparez les wheels sur une machine connectée,
avec **la même version de Python que la cible** (ici 3.12) :

```bash
(cd web && npm ci && npm run build)   # interface web, embarquée dans la wheel
python3.12 -m pip wheel --no-deps -w wheels .
python3.12 -m pip download -d wheels "mcp>=2,<3" "sqlmodel>=0.0.22" "pydantic-settings>=2.2" \
    "fastapi>=0.135"
# PostgreSQL uniquement : python3.12 -m pip download -d wheels psycopg2-binary
```

Copiez ensuite le dossier `wheels/` sur la machine cible.

!!! note "Même plateforme"
    La machine cible doit avoir le même OS et la même architecture que la machine connectée.
    Sinon, ajoutez `--platform` et `--only-binary=:all:` à `pip download`.

Puis, sur la machine cible, en ciblant explicitement Python 3.12 :

```bash
python3.12 -m venv /opt/security-review-mcp/venv
/opt/security-review-mcp/venv/bin/pip install --no-index --find-links wheels security-review-mcp
```

## Lancement

```bash
# stdio : l'hôte lance le processus lui-même (poste développeur)
security-review-mcp

# HTTP : serveur partagé (CI/CD)
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint : http://127.0.0.1:8000/mcp
# interface web : http://127.0.0.1:8000/ui/
```

Pour exposer le serveur HTTP au-delà de localhost, activez
[l'authentification et le TLS](http.md).
