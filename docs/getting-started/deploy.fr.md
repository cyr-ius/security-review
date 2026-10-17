# Mise en service du serveur

Cette page met en place un **serveur partagé** pour une équipe : le contrôleur (interface web,
administration) et le serveur MCP (utilisé par les agents et la CI), sur la même base. Voir
[deux services, deux rôles](../index.md#deux-services-deux-roles).

À la fin, vous disposez :

- d'une interface web où les personnes consultent et trient les rapports ;
- d'un endpoint `/mcp`, protégé par des jetons, auquel se connectent les hôtes des
  développeurs ;
- d'un compte `admin` pour gérer les utilisateurs, les jetons et les règles.

Deux façons : [en ligne de commande](#en-ligne-de-commande) (une machine) ou
[avec Docker Compose](#avec-docker-compose) (conteneurs et PostgreSQL).

## En ligne de commande

### 1. Choisir la base de données

Les deux processus doivent utiliser **la même base** : donnez-leur le même
`SECREVIEW_DATABASE_URL` (voir [Configuration](../reference/configuration.md#base-de-donnees)).

- **SQLite** (par défaut) : uniquement si les deux processus tournent sur la même machine.
  Donnez un chemin absolu pour qu'ils ouvrent le même fichier quel que soit le répertoire d'où
  ils sont lancés.
- **PostgreSQL** : dès qu'ils tournent sur des machines ou des conteneurs différents (extra
  `postgres`).

```bash
export SECREVIEW_DATABASE_URL=sqlite:////var/lib/secreview/security_reports.db
# ou : postgresql+psycopg2://secreview:<password>@db.example.internal:5432/secreview
```

### 2. Préparer la base et le premier administrateur

```bash
security-review-controller db upgrade                       # crée ou migre le schéma
security-review-controller user create admin --role admin   # mot de passe affiché une fois
```

Conservez le mot de passe : il ouvre l'interface web. Changez-le ensuite depuis **Mon compte**.

### 3. Lancer le contrôleur

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface web : http://127.0.0.1:8080/ui/
```

Connectez-vous avec le compte `admin`. Le contrôleur est destiné aux personnes : gardez-le sur
localhost ou sur un réseau interne (voir [Architecture et déploiement](../advanced/architecture.md)).

### 4. Lancer le serveur MCP

Sur la machine seule (essai) :

```bash
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint MCP : http://127.0.0.1:8000/mcp
```

Pour les développeurs et la CI, exposez-le **avec TLS**, avec un certificat reconnu par leurs
postes (voir [TLS](../advanced/http.md#tls)) :

```bash
security-review-mcp --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# endpoint MCP : https://secreview.example.internal:8443/mcp
```

Le serveur MCP refuse de démarrer tant que le schéma n'est pas migré (étape 2).

### 5. Donner l'accès aux agents

Le serveur MCP exige un jeton **dès qu'un jeton existe** en base. Créez le premier maintenant :

```bash
security-review-controller token create --label alice   # jeton mcp, affiché une fois
```

!!! warning "Tant qu'aucun jeton n'existe, `/mcp` est ouvert"
    Quiconque atteint l'endpoint peut alors l'utiliser. Créez un jeton avant d'exposer le
    serveur.

Ensuite, deux façons de donner un jeton à chaque développeur et à chaque pipeline :

- **Enrôlement** (activé par défaut) : le développeur connecte son hôte sans jeton, l'agent en
  demande un à la première revue, et un administrateur l'approuve dans l'écran **Jetons**.
  Rien à préparer : voir [Obtenir un jeton](host.md#obtenir-un-jeton-enrolement).
- **Créé par l'administrateur** : `security-review-controller token create --label <nom>`, par
  exemple pour un pipeline, puis remis à son propriétaire.

### 6. Vérifier

```bash
curl http://127.0.0.1:8080/healthz   # contrôleur : {"status":"ok"}
curl http://127.0.0.1:8000/healthz   # serveur MCP : {"status":"ok"}
```

## Avec Docker Compose

Le fichier `docker-compose.yml` du dépôt réalise les étapes 1 à 4 avec PostgreSQL : base,
migration, contrôleur et serveur MCP. Le compte `admin` est créé au premier lancement, avec son
mot de passe dans les journaux :

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose logs controller                     # mot de passe admin initial
docker compose exec controller security-review-controller token create --label alice
```

L'interface web répond sur `http://127.0.0.1:8080/ui/`, l'endpoint MCP sur
`http://127.0.0.1:8000/mcp`. Les deux ports ne sont publiés que sur `127.0.0.1` : pour les
ouvrir à l'équipe, ajoutez le TLS et renseignez `PUBLISH_ADDRESS` (voir
[Docker Compose avec PostgreSQL](../advanced/docker.md#docker-compose-avec-postgresql)).

## Étape suivante

[Connectez l'hôte](host.md) de chaque développeur au serveur MCP. Pour aller plus loin :
[jetons, enrôlement et TLS](../advanced/http.md), [Kubernetes](../advanced/architecture.md#kubernetes),
[connexion SSO](../advanced/sso.md).
