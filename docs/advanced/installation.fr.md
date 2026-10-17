# Installation : autres cas

L'installation courante est décrite dans [Installation](../getting-started/installation.md).
Cette page couvre l'installation depuis les sources, sans accès Internet, et la mise à jour
depuis la version 1.x.

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

## Mise à jour depuis la version 1.x

La version 2 sépare le serveur MCP et le contrôleur, et gère le schéma avec Alembic :

1. Mettez à jour le paquet ou l'image, puis lancez **une fois**
   `security-review-controller db upgrade`. Une base créée par la version 1.x est reconnue et
   complétée (colonnes et tables manquantes, jetons multi-projets), sans perte de données.
2. Lancez le contrôleur (`security-review-controller serve`) à côté du serveur MCP : celui-ci ne
   sert plus `/ui/` ni l'API REST, à l'exception de l'enrôlement public `/api/v1/enroll`.
3. Remplacez `security-review-mcp token|rules|gate|sarif|trend|advisories|deps|code` par
   `security-review-controller …` dans vos scripts et pipelines. Les anciennes formes
   fonctionnent encore pendant la version 2, avec un avertissement.
4. Le compte administrateur initial (`SECREVIEW_AUTH_BOOTSTRAP_ADMIN`) est désormais
   créé par le contrôleur : c'est le [compte `admin`](../usage/web-interface.md#premier-administrateur)
   de l'interface web, et non plus un jeton `bootstrap-admin`.
