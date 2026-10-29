# Installation manuelle (sans conteneur)

Cette page installe security-review-mcp **tout-en-un** sur un seul serveur Linux, sans
Docker : le **serveur Controller**, le **serveur MCP** et leur **base SQLite** tournent sur la même
machine, avec le même utilisateur. Elle convient à un essai, à une petite équipe ou à un
serveur où les conteneurs ne sont pas autorisés.

Pour un déploiement d'équipe, préférez [Docker Compose](../../getting-started/deploy.md#avec-docker-compose)
ou [Kubernetes](kubernetes.md) : PostgreSQL est inclus, et les services redémarrent seuls.

```text
 agents (VS Code, Claude), CI ──▶ serveur MCP         :8000 ──┐
                                                              ├──▶ fichier SQLite
 personnes (navigateur) ────────▶ serveur Controller  :8080 ──┘
                    └──────────────────── une machine ───────────────────┘
```

## 1. Installer le paquet

Python 3.14 ou plus récent, avec [uv](https://docs.astral.sh/uv/getting-started/installation/) :

```bash
uv venv /opt/security-review-mcp && source /opt/security-review-mcp/bin/activate
uv pip install security-review
```

## 2. Choisir la base de données

Les deux processus doivent utiliser **la même base** : donnez-leur le même
`SECREVIEW_DATABASE_URL` (voir [Base de données](../database.md#sqlite-ou-postgresql)).
En tout-en-un, SQLite suffit : donnez un chemin absolu pour que les deux processus ouvrent le
même fichier quel que soit le répertoire d'où ils sont lancés.

```bash
sudo install -d -o "$USER" -m 700 /var/lib/secreview
export SECREVIEW_DATABASE_URL=sqlite:////var/lib/secreview/security_reports.db
# ou, avec un PostgreSQL existant (uv pip install "security-review[postgres]") :
# postgresql+psycopg2://secreview:<password>@db.example.internal:5432/secreview
```

## 3. Préparer la base et le premier administrateur

```bash
security-review-controller db upgrade                       # crée ou migre le schéma
security-review-controller user create admin --group administrators   # mot de passe affiché une fois
```

Conservez le mot de passe : il ouvre l'interface web. Changez-le ensuite depuis **Mon compte**.

## 4. Lancer le serveur Controller

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface web : http://127.0.0.1:8080/ui/
```

Connectez-vous avec le compte `admin`. Le serveur Controller est destiné aux personnes et aux pipelines :
exposez-le avec TLS (voir [Serveur Controller](../architecture/controller.md#exposition)).

## 5. Lancer le serveur MCP

Dans un autre terminal, avec le même `SECREVIEW_DATABASE_URL`. Sur la machine seule (essai) :

```bash
security-review-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint MCP : http://127.0.0.1:8000/mcp
```

Pour les développeurs et la CI, exposez-le **avec TLS**, avec un certificat reconnu par leurs
postes (voir [TLS](../tls.md)) :

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# endpoint MCP : https://secreview.example.internal:8443/mcp
```

Le serveur MCP refuse de démarrer tant que le schéma n'est pas migré (étape 3).

## 6. Donner l'accès aux agents

Le serveur MCP exige un jeton, même tant qu'aucun n'existe en base (il ne sert alors que le
serveur d'enrôlement). Créez le premier maintenant :

```bash
security-review-controller token create --label alice   # jeton mcp, affiché une fois
```

!!! note "Serveur ouvert sur localhost"
    Un serveur qui écoute sur localhost, sans aucun jeton, accepte toutes les requêtes. Ailleurs,
    seul `SECREVIEW_ALLOW_UNAUTHENTICATED=true` l'ouvre (voir
    [Jetons Bearer](../bearer-tokens.md)).

Ensuite, deux façons de donner un jeton à chaque développeur et à chaque pipeline :

- **Jeton personnel** (avec l'enrôlement, activé par défaut) : le développeur connecte son hôte
  sans jeton, l'agent l'envoie vers l'interface web à la première revue, où il crée un jeton
  MCP personnel ; à la revue suivante, l'agent demande le projet, qu'un administrateur valide
  (page **Projets**), ce qui lui en donne l'accès. Définissez
  `SECREVIEW_PUBLIC_URL` sur le serveur Controller (ou la page **Général**) pour que
  l'agent donne le lien : voir
  [Obtenir un jeton](../../getting-started/host.md#obtenir-un-jeton).
- **Créé par l'administrateur** : `security-review-controller token create --label <nom>`, par
  exemple pour un pipeline, puis remis à son propriétaire.

## 7. Vérifier et se connecter

```bash
curl http://127.0.0.1:8080/healthz   # serveur Controller : {"status":"ok"}
curl http://127.0.0.1:8000/healthz   # serveur MCP : {"status":"ok"}
```

Connectez-vous à l'interface web sur `http://127.0.0.1:8080/ui/` avec le compte `admin`, puis
créez un compte pour chaque personne dans la page **Utilisateurs** (voir les
[comptes utilisateurs](../../usage/user-accounts.md)).

**Étape suivante :** [connectez l'hôte](../../getting-started/host.md) de chaque développeur au
serveur MCP.
