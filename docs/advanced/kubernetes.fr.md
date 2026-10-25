# Kubernetes

Deux manifestes déploient tout dans le namespace `secreview` :
[`examples/kubernetes/postgres.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/{{ release_tag }}/examples/kubernetes/postgres.yaml)
(PostgreSQL, image officielle) et
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/{{ release_tag }}/examples/kubernetes/security-review.yaml)
(contrôleur et serveur MCP, image publiée `ghcr.io/cyr-ius/security-review-mcp:latest-pg`).

## Déploiement

=== "Avec PostgreSQL (image officielle)"

    Copiez-collez tout le bloc : il crée la base, son mot de passe et les Secrets, puis démarre
    security-review-mcp et donne le mot de passe du premier administrateur.

    ```bash
    kubectl create namespace secreview

    # 1. PostgreSQL (image officielle) : un mot de passe, dans le Secret de la base et dans l'URL
    PGPASSWORD="$(openssl rand -hex 24)"
    kubectl -n secreview create secret generic secreview-postgres \
        --from-literal=POSTGRES_PASSWORD="$PGPASSWORD"
    kubectl -n secreview create secret generic secreview-db \
        --from-literal=SECREVIEW_DATABASE_URL="postgresql+psycopg2://secreview:${PGPASSWORD}@secreview-postgres:5432/secreview"
    unset PGPASSWORD
    kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review-mcp/{{ release_tag }}/examples/kubernetes/postgres.yaml
    kubectl -n secreview rollout status statefulset/secreview-postgres

    # 2. security-review-mcp : secret des sessions, contrôleur et serveur MCP
    kubectl -n secreview create secret generic secreview-controller \
        --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
    kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review-mcp/{{ release_tag }}/examples/kubernetes/security-review.yaml
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

=== "Avec un PostgreSQL existant"

    Une base managée (Amazon RDS, Azure Database for PostgreSQL, Google Cloud SQL...) ou un
    opérateur (CloudNativePG...) qui contient une base `secreview` vide, propriété d'un rôle
    `secreview`. Remplacez `<password>` et `<host>` ; ajoutez `?sslmode=verify-full` à l'URL
    quand le serveur propose le TLS.

    ```bash
    kubectl create namespace secreview
    kubectl -n secreview create secret generic secreview-db \
        --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
    kubectl -n secreview create secret generic secreview-controller \
        --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
    kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review-mcp/{{ release_tag }}/examples/kubernetes/security-review.yaml
    kubectl -n secreview rollout status deploy/secreview-controller
    kubectl -n secreview rollout status deploy/secreview-mcp
    kubectl -n secreview exec deploy/secreview-controller -c controller -- \
        security-review-controller user reset-password admin
    ```

## Contenu des manifestes

`postgres.yaml` contient un **StatefulSet `secreview-postgres`** (image officielle
`postgres:18-alpine`, une instance, volume de 10 Gio, conteneur non root avec un système de
fichiers en lecture seule), son Service et une **NetworkPolicy** qui ne laisse que les pods de
security-review-mcp atteindre le port `5432`. En production, préférez une base managée ou un
opérateur, qui gèrent la réplication, les sauvegardes et les mises à niveau.

`security-review.yaml` contient :

- un **Deployment `secreview-controller`** (une réplique, stratégie `Recreate`) dont l'init
  container lance `security-review-controller db upgrade` à chaque déploiement ;
- un **Deployment `secreview-mcp`**, qui vérifie seulement le schéma ;
- le **Secret `secreview-controller`**, créé à la main (voir [Secrets](#secrets)), avec
  `SECREVIEW_SECRET_KEY` : sans lui, le contrôleur tire un secret de session aléatoire à
  chaque démarrage, les sessions web prendraient donc fin à chaque redémarrage et ne seraient
  pas partagées entre réplicas (voir
  [Connexion et sessions](../usage/web-interface.md#connexion-et-sessions)) ;
- un Service par processus, des sondes `readiness` et `liveness` sur `/healthz`, des
  conteneurs non root en système de fichiers en lecture seule, sans capacité Linux ;
- une **NetworkPolicy** qui limite l'accès au contrôleur aux pods du namespace et à
  l'ingress controller (adaptez son label).

Contenu des manifestes de la version `{{ release_tag }}`, appliqués par les commandes ci-dessus :

=== "postgres.yaml"

    ```yaml
    --8<-- "kubernetes/postgres.yaml"
    ```

=== "security-review.yaml"

    ```yaml
    --8<-- "kubernetes/security-review.yaml"
    ```

## Secrets

Les Secrets (`secreview-postgres`, `secreview-db`, `secreview-controller`) ne sont pas dans les
exemples, pour que `kubectl apply` ne remplace jamais leurs
valeurs. Le mot de passe de `secreview-postgres` et celui de l'URL de `secreview-db` doivent être
identiques. Pour les déclarer en manifestes plutôt qu'avec `kubectl create secret` (GitOps),
utilisez `kind: Secret` :

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secreview-postgres
  namespace: secreview
type: Opaque
stringData:
  POSTGRES_PASSWORD: <password>
---
apiVersion: v1
kind: Secret
metadata:
  name: secreview-db
  namespace: secreview
type: Opaque
stringData:
  SECREVIEW_DATABASE_URL: postgresql+psycopg2://secreview:<password>@secreview-postgres:5432/secreview
---
apiVersion: v1
kind: Secret
metadata:
  name: secreview-controller
  namespace: secreview
type: Opaque
stringData:
  # openssl rand -hex 32 (32 caractères au moins, inchangé d'un déploiement à l'autre)
  SECREVIEW_SECRET_KEY: <64 caractères hexadécimaux>
  # Proxy avec identifiants (téléchargement OSV, OIDC), facultatif
  # HTTPS_PROXY: http://user:<password>@proxy.example.com:3128
```

`stringData` reçoit les valeurs en clair ; Kubernetes les stocke encodées en base64 dans `data`.
Ne commitez jamais ce fichier avec de vraies valeurs : chiffrez-le (Sealed Secrets, SOPS) ou
laissez un opérateur comme External Secrets le créer depuis votre coffre. Les pods lisent les
Secrets au démarrage : après un changement, redémarrez-les
(`kubectl -n secreview rollout restart deploy/secreview-controller`). Changer
`SECREVIEW_SECRET_KEY` termine toutes les sessions web.

## Image, exposition et administration

Le manifeste utilise l'image publiée `ghcr.io/cyr-ius/security-review-mcp:latest-pg`, qui
contient le pilote PostgreSQL : épinglez une version (`X.Y.Z-pg`) en production, ou utilisez
votre propre image construite avec l'extra `postgres`. Exposez le Service `secreview-mcp` aux agents et à la CI par un Ingress avec
TLS. Gardez le contrôleur interne (`kubectl port-forward`, VPN ou Ingress restreint aux
administrateurs). Derrière l'Ingress, réglez `SECREVIEW_FORWARDED_ALLOW_IPS` (en commentaire dans
la ConfigMap) sur la plage d'adresses des pods de l'ingress controller : sinon tous les clients
partagent leur adresse pour la limitation des connexions et les limites d'enrôlement. Les
commandes d'administration s'exécutent dans son pod :

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list
```

## Mise à jour OSV

Pour la [mise à jour quotidienne des avis OSV](dependencies.md#mise-a-jour-automatique-par-le-controleur),
décommentez `SECREVIEW_OSV_AUTO_UPDATE` (et au besoin `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
et `NO_PROXY`, dans le Secret `secreview-controller` si le proxy contient des identifiants) sur
le conteneur `controller`, et autorisez sa sortie vers osv.dev ou votre miroir (ou le proxy) si une NetworkPolicy d'egress s'applique. Le serveur MCP
n'a besoin d'aucune sortie. La documentation Swagger de l'API REST (`/api/docs`) reste
désactivée tant que vous ne décommentez pas `SECREVIEW_SWAGGER_ENABLED`.

## Plusieurs réplicas

!!! warning "Plusieurs réplicas du serveur MCP"
    Les sessions MCP (transport streamable HTTP) sont gardées en mémoire par le pod qui les a
    ouvertes. Avant d'augmenter `replicas`, configurez l'Ingress pour envoyer toutes les
    requêtes d'une session au même pod (affinité sur l'en-tête `Mcp-Session-Id`, ou à défaut
    affinité par cookie ou par adresse). Le contrôleur peut, lui, avoir plusieurs réplicas, à
    condition que la migration soit faite par une seule tâche (`SECREVIEW_DB_AUTO_UPGRADE=false`
    sur les réplicas).
