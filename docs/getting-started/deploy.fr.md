# Mise en service du serveur

Cette page met en place le **mode partagé (HTTP)** pour une équipe : le contrôleur (interface web,
administration) et le serveur MCP (utilisé par les agents et la CI), sur la même base. Voir
[deux services, deux rôles](../index.md#deux-services-deux-roles).

À la fin, vous disposez :

- d'une interface web où les personnes consultent et trient les rapports ;
- d'un endpoint `/mcp`, protégé par des jetons, auquel se connectent les hôtes des
  développeurs ;
- d'un compte `admin` pour gérer les utilisateurs, les jetons et les règles.

Sans conteneur, tout-en-un sur un serveur Linux : voir la section Avancé
[Installation manuelle (sans conteneur)](../advanced/manual-install.md).

## Avec Docker Compose

Le fichier `docker-compose.yml` démarre une base de donnée PostgreSQL,
le contrôleur et le serveur MCP.

Copiez-collez ce code dans un dossier vide.
Cela télécharge le fichier `docker-compose.yml`, génère les secrets dans `.env`et démarre les services.
et affiche le mot de passe du compte `admin` et crée un jeton à positionner dans le mcp.json de l'IDE d'Alice.

```bash
mkdir security-review-mcp && cd security-review-mcp
curl -fsSLO https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/docker/docker-compose.yml
(umask 077 && printf 'POSTGRES_PASSWORD=%s\nSECREVIEW_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env)
docker compose up -d --wait
docker compose exec controller security-review-controller user reset-password admin   # mot de passe admin initial
docker compose exec controller security-review-controller token create --label alice   # jeton d'un agent
```

L'interface web répond sur `http://127.0.0.1:8080/ui/`. Connectez-vous avec le compte `admin`,
et changer le mot de passe à la première connexion.

Le serveur MCP sur `http://127.0.0.1:8000/mcp`.

!!! warning "La CLI est le seul moyen d'obtenir le mot de passe initial"
    Aucune variable ne le définit et les journaux ne l'affichent jamais : lancez
    `user reset-password admin` dans le conteneur, et traitez ce qu'elle affiche comme un secret.
    Si vous le perdez, relancez la commande (l'ancien est aussitôt invalidé).

**Pour plus d'informations :** voir [Docker](../advanced/docker.md) dans la section **Avancé**
(ouverture à l'équipe, TLS, mise à jour OSV, sauvegardes, mise à niveau de PostgreSQL, sans Docker
Compose).

## Avec Kubernetes

Copiez-collez tout le bloc : il déploie PostgreSQL (image officielle), le contrôleur et le
serveur MCP (image publiée) dans le namespace `secreview`, puis donne le mot de passe du premier
administrateur et un jeton. Un init container migre le schéma.

```bash
kubectl create namespace secreview

# 1. PostgreSQL (image officielle) : un mot de passe, dans le Secret de la base et dans l'URL
PGPASSWORD="$(openssl rand -hex 24)"
kubectl -n secreview create secret generic secreview-postgres \
    --from-literal=POSTGRES_PASSWORD="$PGPASSWORD"
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL="postgresql+psycopg2://secreview:${PGPASSWORD}@secreview-postgres:5432/secreview"
unset PGPASSWORD
kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/kubernetes/postgres.yaml
kubectl -n secreview rollout status statefulset/secreview-postgres

# 2. security-review-mcp : secret des sessions, contrôleur et serveur MCP
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/kubernetes/security-review.yaml
kubectl -n secreview rollout status deploy/secreview-controller
kubectl -n secreview rollout status deploy/secreview-mcp

# 3. Premier administrateur et jeton d'un agent (chaque secret n'est affiché qu'une fois)
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller user reset-password admin
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token create --label alice

# 4. Interface web sur http://127.0.0.1:8080/ui/
kubectl -n secreview port-forward svc/secreview-controller 8080:80
```

Le contrôleur n'est pas exposé hors du cluster : vous ouvrez l'interface web depuis votre poste
avec la dernière commande du bloc (`port-forward`), qui reste active tant que le terminal est
ouvert.

Pour que les développeurs et la CI atteignent le serveur MCP, exposez le Service
`secreview-mcp` par un Ingress avec TLS. Renseignez alors `SECREVIEW_FORWARDED_ALLOW_IPS` (en
commentaire dans la ConfigMap du manifeste) avec la plage d'adresses des pods de l'ingress
controller : sans ce réglage, tous les clients semblent venir de la même adresse, celle de
l'Ingress.

**Pour plus d'informations :** voir [Kubernetes](../advanced/kubernetes.md) dans la section
**Avancé** (PostgreSQL existant, contenu des manifestes, Secrets, exposition, mise à jour OSV,
plusieurs réplicas).

## Étape suivante

[Connectez l'hôte](host.md) de chaque développeur au serveur MCP. Pour aller plus loin :
[jetons, enrôlement et TLS](../advanced/http.md), [connexion OIDC](../advanced/sso.md).
