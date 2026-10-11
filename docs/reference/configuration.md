# Configuration

Le serveur lit des variables d'environnement préfixées `SECREVIEW_`, ou un fichier `.env` dans
le répertoire courant (voir `.env.example`).

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_DATABASE_URL` | `sqlite:///./security_reports.db` | URL SQLAlchemy de la base |
| `SECREVIEW_DATABASE_ECHO` | `false` | Journalise les requêtes SQL |
| `SECREVIEW_TRANSPORT` | `stdio` | `stdio` ou `streamable-http` |
| `SECREVIEW_HOST` | `127.0.0.1` | Adresse d'écoute (HTTP) |
| `SECREVIEW_PORT` | `8000` | Port d'écoute (HTTP) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Génère le mot de passe admin initial, stocké en base (empreinte uniquement) |
| `SECREVIEW_ENROLLMENT` | `true` | [Enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton) : un client sans jeton peut demander un jeton de projet (serveur MCP restreint, `POST /api/v1/enroll`), actif après approbation |
| `SECREVIEW_TLS_CERTFILE` | — | Certificat : active le TLS |
| `SECREVIEW_TLS_KEYFILE` | — | Clé privée |
| `SECREVIEW_TLS_KEYFILE_PASSWORD` | — | Mot de passe de la clé privée |
| `SECREVIEW_TLS_CLIENT_CA` | — | CA cliente : active le TLS mutuel |
| `SECREVIEW_WEB_UI` | `true` | Active l'[interface web](../utilisation/interface-web.md) et l'API REST (HTTP) |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'interface web |
| `SECREVIEW_LOG_LEVEL` | `INFO` | Niveau de journalisation (sur stderr) |
| `SECREVIEW_MAX_CONTENT_CHARS` | `200000` | Taille maximale du contenu passé à `scan_code` |
| `SECREVIEW_MAX_FINDINGS_PER_REPORT` | `500` | Nombre maximal de findings par rapport |
| `SECREVIEW_MAX_DEPENDENCY_CHARS` | `1000000` | Taille maximale d'un manifeste passé à `scan_dependencies` |
| `SECREVIEW_MAX_LIST_LIMIT` | `100` | Taille maximale d'une page de résultats |

Les jetons Bearer ne se configurent pas par variable : ils sont stockés en base et gérés avec
`security-review-mcp token` (voir [Serveur HTTP, authentification et TLS](../demarrage/http.md)).
Les règles internes non plus : elles sont stockées en base et gérées avec
`security-review-mcp rules` (voir [Règles internes](../utilisation/regles.md)).

## Base de données

SQLite par défaut. Pour PostgreSQL (extra `postgres`) :

```bash
SECREVIEW_DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/secreview
```

Les tables sont créées au démarrage (`create_all`) et les colonnes facultatives ajoutées par les
versions récentes sont ajoutées automatiquement aux bases existantes. Pour des migrations plus
complexes en production, ajouter Alembic.
