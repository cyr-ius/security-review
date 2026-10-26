# Installation : autres cas

Les installations courantes sont décrites dans [Mise en service du serveur](../../getting-started/deploy.md)
(conteneurs) et [Mode local (stdio)](../../getting-started/stdio.md#installation) (paquet PyPI).
Cette page couvre l'installation depuis les sources et sans accès Internet.

## Depuis les sources

```bash
git clone https://github.com/cyr-ius/security-review.git
cd security-review
uv sync --extra dev               # ajouter --extra postgres pour PostgreSQL
cp .env.example .env
uv run pytest && uv run ruff check .
```

L'[interface web](../../usage/index.md) est une application Angular à compiler
(Node.js 22.22.3+ ou 24.15+, requis par Angular 22) ; sans elle, le contrôleur ne sert que l'API REST :

```bash
cd web && npm ci && npm run build   # écrit dans src/security_review_mcp/webui/
```

## Installation hors ligne

Pour un environnement sans accès Internet, préparez les wheels sur une machine connectée,
avec **la même version de Python que la cible** (ici 3.14) :

```bash
(cd web && npm ci && npm run build)   # interface web, embarquée dans la wheel
uv build --wheel --out-dir wheels
python3.14 -m pip download -d wheels "mcp>=2,<3" "sqlmodel>=0.0.22" "pydantic-settings>=2.2" \
    "fastapi>=0.135" "tomlkit>=0.13" "alembic>=1.13"
# PostgreSQL uniquement : python3.14 -m pip download -d wheels psycopg2-binary
```

uv n'a pas d'équivalent de `pip download` : les dépendances sont téléchargées avec pip. Copiez
ensuite le dossier `wheels/` sur la machine cible.

!!! note "Même plateforme"
    La machine cible doit avoir le même OS et la même architecture que la machine connectée.
    Sinon, ajoutez `--platform` et `--only-binary=:all:` à `pip download`.

Puis, sur la machine cible (uv est un exécutable unique : copiez-le avec les wheels), en ciblant
explicitement Python 3.14 :

```bash
uv venv --python 3.14 /opt/security-review-mcp/venv
uv pip install --python /opt/security-review-mcp/venv --no-index --find-links wheels security-review
```
