# Mise en service du serveur

Cette page met en place un **serveur partagé** pour une équipe : le contrôleur (interface web,
administration) et le serveur MCP (utilisé par les agents et la CI), sur la même base. Voir
[deux services, deux rôles](../index.md#deux-services-deux-roles).

À la fin, vous disposez :

- d'une interface web où les personnes consultent et trient les rapports ;
- d'un endpoint `/mcp`, protégé par des jetons, auquel se connectent les hôtes des
  développeurs ;
- d'un compte `admin` pour gérer les utilisateurs, les jetons et les règles.

Trois façons : [en ligne de commande](#en-ligne-de-commande) (une machine),
[avec Docker Compose](#avec-docker-compose) (conteneurs et PostgreSQL) ou
[avec Kubernetes](#avec-kubernetes) (cluster et base PostgreSQL existante).

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
security-review-controller user create admin --group administrators   # mot de passe affiché une fois
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
security-review-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
# endpoint MCP : http://127.0.0.1:8000/mcp
```

Pour les développeurs et la CI, exposez-le **avec TLS**, avec un certificat reconnu par leurs
postes (voir [TLS](../advanced/http.md#tls)) :

```bash
security-review-mcp serve --transport streamable-http --host 0.0.0.0 --port 8443 \
    --tls-certfile /etc/secreview/tls/cert.pem --tls-keyfile /etc/secreview/tls/key.pem
# endpoint MCP : https://secreview.example.internal:8443/mcp
```

Le serveur MCP refuse de démarrer tant que le schéma n'est pas migré (étape 2).

### 5. Donner l'accès aux agents

Le serveur MCP exige un jeton, même tant qu'aucun n'existe en base (il n'accepte alors que les
enrôlements). Créez le premier maintenant :

```bash
security-review-controller token create --label alice   # jeton mcp, affiché une fois
```

!!! note "Serveur ouvert sur localhost"
    Un serveur qui écoute sur localhost, sans aucun jeton, accepte toutes les requêtes. Ailleurs,
    seul `SECREVIEW_ALLOW_UNAUTHENTICATED=true` l'ouvre (voir
    [Jetons Bearer](../advanced/http.md#jetons-bearer)).

Ensuite, deux façons de donner un jeton à chaque développeur et à chaque pipeline :

- **Jeton personnel** (avec l'enrôlement, activé par défaut) : le développeur connecte son hôte
  sans jeton, l'agent demande le projet à la première revue et l'envoie vers l'interface web, où
  il crée un jeton MCP personnel ; un administrateur valide le projet (écran **Projets**) et
  l'ajoute à son groupe. Définissez
  `SECREVIEW_WEB_URL` pour que l'agent donne le lien : voir
  [Obtenir un jeton](host.md#obtenir-un-jeton).
- **Créé par l'administrateur** : `security-review-controller token create --label <nom>`, par
  exemple pour un pipeline, puis remis à son propriétaire.

### 6. Vérifier

```bash
curl http://127.0.0.1:8080/healthz   # contrôleur : {"status":"ok"}
curl http://127.0.0.1:8000/healthz   # serveur MCP : {"status":"ok"}
```

### 7. Connectez vous

Connecter vous à l'interface

http://127.0.0.1:8080/ui/

### 8. Docker

Les mêmes opérations au sein de containers Docker

Une seule image, deux conteneurs qui partagent la base (voir [Architecture et déploiement](architecture.md)) :

- le **serveur MCP**, point d'entrée par défaut de l'image (`security-review-mcp`, commande par
  défaut `serve` : stdio ; ajoutez `--transport streamable-http` pour HTTP) ;
- le **contrôleur** (API REST, interface web, administration), lancé avec
  `--entrypoint security-review-controller`.

Avec l'[authentification et le TLS intégrés](http.md) (ou derrière un reverse proxy qui s'en charge)


```bash
DB=postgresql+psycopg2://user:pass@db:5432/secreview

# 1. Schéma (Alembic) : à relancer après chaque mise à jour de l'image
docker run --rm -e SECREVIEW_DATABASE_URL=$DB \
    --entrypoint security-review-controller security-review-mcp:pg db upgrade

# 2. Contrôleur : interface web et API, de préférence sur un réseau interne
docker run -d --name secreview-controller -p 127.0.0.1:8080:8000 \
    -e SECREVIEW_DATABASE_URL=$DB -e SECREVIEW_DB_AUTO_UPGRADE=false \
    --entrypoint security-review-controller \
    security-review-mcp:pg serve --host 0.0.0.0 --port 8000

# 3. Serveur MCP : exposé aux agents et à la CI
docker run -d --name secreview-mcp -p 8443:8443 \
    -e SECREVIEW_DATABASE_URL=$DB \
    -v ./tls:/etc/secreview/tls:ro \
    -e SECREVIEW_TLS_CERTFILE=/etc/secreview/tls/cert.pem \
    -e SECREVIEW_TLS_KEYFILE=/etc/secreview/tls/key.pem \
    security-review-mcp:pg serve --transport streamable-http --host 0.0.0.0 --port 8443
```

Les fichiers montés doivent être lisibles par l'utilisateur du conteneur (uid `10001`). Le
serveur MCP refuse de démarrer tant que le schéma n'est pas migré. Au premier démarrage du
contrôleur.

Définissez-le mot de passe du compte `admin`via la commande
`docker exec secreview-controller security-review-controller user reset-password admin`

Connectez-vous sur l'interface (`/ui/`) avec l'identifiant `admin`, puis choisissez votre
propre mot de passe dans **Mon compte**.
Créez ensuite un compte par personne dans l'écran **Utilisateurs**
(voir les [comptes utilisateurs](../usage/web-interface.md#comptes-utilisateurs)).

!!! warning "La CLI est le seul moyen d'obtenir le mot de passe initial"
    Aucune variable ne le définit et les journaux ne l'affichent jamais : lancez
    `user reset-password admin` dans le conteneur, et traitez ce qu'elle affiche comme un secret.
    Si vous le perdez, relancez la commande (l'ancien est aussitôt invalidé).


## Avec Docker Compose

Le fichier `docker-compose.yml` du dépôt réalise les étapes 1 à 4 avec PostgreSQL : base,
migration, contrôleur et serveur MCP. Le compte `admin` est créé au premier lancement ; définissez
son mot de passe avec la CLI, qui l'affiche une fois :

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" > .env
docker compose up -d --build
docker compose exec controller security-review-controller user reset-password admin   # mot de passe admin initial
docker compose exec controller security-review-controller token create --label alice
```

L'interface web répond sur `http://127.0.0.1:8080/ui/`, l'endpoint MCP sur `http://127.0.0.1:8000/mcp`.
Les deux ports ne sont publiés que sur `127.0.0.1`.

Pour ouvrir à l'équipe, ajoutez le TLS et renseignez `DOCKER_PUBLISH_ADDRESS`. (voir [Docker Compose avec PostgreSQL](../advanced/docker.md#docker-compose-avec-postgresql)).

## Avec Kubernetes

Le manifeste
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/master/examples/kubernetes/security-review.yaml)
réalise les étapes 2 à 4 sur une base PostgreSQL existante.
un init container migre le schéma, puis le contrôleur et le serveur MCP démarrent dans deux Deployments.
Le compte `admin` est créé au premier lancement ; définissez son mot de passe avec la CLI, qui l'affiche une fois.

Avant de l'appliquer, remplacez l'image `registry.example.com/security-review-mcp:pg` par une
image qui contient le pilote PostgreSQL, par exemple `ghcr.io/cyr-ius/security-review-mcp:latest-pg`
(voir [Installation](installation.md)).

Le Secret `secreview-controller` contient le secret de signature des sessions web : sans lui, le contrôleur le génère de façon aléatoire à chaque démarrage mettant fin aux sessions (manifeste du Secret : voir [Kubernetes](../advanced/architecture.md#kubernetes)).


```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f examples/kubernetes/security-review.yaml
kubectl -n secreview exec deploy/secreview-controller -c controller -- security-review-controller user reset-password admin   # mot de passe admin initial
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token create --label alice
```

Le contrôleur reste interne.

Ouvrez l'interface web avec `kubectl -n secreview port-forward svc/secreview-controller 8080:80`.
Exposez le Service `secreview-mcp` aux développeurs et à la CI par un Ingress avec TLS, et réglez
 `SECREVIEW_FORWARDED_ALLOW_IPS` sur la plage d'adresses des pods
de l'ingress controller. Contenu du manifeste, mise à jour OSV et réplicas multiples : voir
[Kubernetes](../advanced/architecture.md#kubernetes).

## Étape suivante

[Connectez l'hôte](host.md) de chaque développeur au serveur MCP. Pour aller plus loin :
[jetons, enrôlement et TLS](../advanced/http.md), [connexion OIDC](../advanced/sso.md).
