# Kubernetes

Deux manifestes déploient tout dans le namespace `secreview` :
[`examples/kubernetes/postgres.yaml`](https://github.com/cyr-ius/security-review/blob/{{ release_tag }}/examples/kubernetes/postgres.yaml)
(PostgreSQL, image officielle) et
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review/blob/{{ release_tag }}/examples/kubernetes/security-review.yaml)
(serveur Controller et serveur MCP, image publiée `ghcr.io/cyr-ius/security-review:latest`).

## Déploiement

Le bloc qui déploie tout, avec le PostgreSQL de `postgres.yaml`, est dans
[Mise en service du serveur](../../getting-started/deploy.md#avec-kubernetes).

Avec un PostgreSQL existant : une base managée (Amazon RDS, Azure Database for PostgreSQL, Google Cloud SQL...) ou un
opérateur (CloudNativePG...) qui contient une base `secreview` vide, propriété d'un rôle
`secreview`. Remplacez `<password>` et `<host>` ; ajoutez `?sslmode=verify-full` à l'URL
quand le serveur propose le TLS.

```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/kubernetes/security-review.yaml
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

- un **Deployment `secreview-controller`** (une réplique, stratégie `Recreate`), qui migre le
  schéma à son démarrage (une sonde `startup` lui laisse jusqu'à 10 minutes) ;
- un **Deployment `secreview-mcp`**, qui vérifie seulement le schéma à son démarrage ;
- une **ConfigMap `secreview-config`** partagée par les deux processus ;
- un Service par processus, des sondes `readiness` et `liveness` sur `/healthz`, des
  conteneurs non root en système de fichiers en lecture seule, sans capacité Linux ;
- une **NetworkPolicy** qui limite l'accès au serveur Controller aux pods du namespace et à
  l'ingress controller (adaptez son label).

Le serveur Controller lit aussi le **Secret `secreview-controller`**, créé à la main (voir
[Secrets](#secrets)), avec `SECREVIEW_SECRET_KEY` : sans lui, le serveur Controller tire un secret de
session aléatoire à chaque démarrage, les sessions web prendraient donc fin à chaque
redémarrage et ne seraient pas partagées entre réplicas (voir
[Connexion et sessions](../architecture/controller.md#connexion-et-sessions)).

Contenu des manifestes de la version `{{ release_tag }}`, appliqués par ces commandes :

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

Le manifeste utilise l'image publiée `ghcr.io/cyr-ius/security-review:latest`, qui
contient le pilote PostgreSQL : épinglez une version (`X.Y.Z`) en production. Exposez chaque
Service par son propre Ingress avec TLS : un exemple, commenté, termine `security-review.yaml`
(un hôte par service, ingress-nginx et cert-manager).

| Service | Atteint par | Ingress |
|---|---|---|
| `secreview-mcp` | les agents (MCP sur `/mcp`, et `/.well-known/oauth-protected-resource` avec la [connexion OAuth](../mcp-oauth.md)) | vers tous les postes des développeurs |
| `secreview-controller` | les personnes (interface web `/ui`, jetons MCP et CI personnels), la CI (`security-review-ci` appelle `/api/v1/ci`) et, avec la connexion OAuth, les hôtes MCP (`/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/revoke`) | vers les développeurs et les runners de CI ; `kubectl port-forward` suffit pour un premier essai |

Avec un hôte par Service, chaque chemin va à son Service : les chemins OAuth n'ont besoin
d'aucune règle propre. Avec un seul hôte pour les deux, routez `/mcp` et
`/.well-known/oauth-protected-resource` vers `secreview-mcp`, tout le reste vers
`secreview-controller`.

Ensuite, dans la ConfigMap :

- réglez `SECREVIEW_CONTROLLER_URL` sur l'URL publique racine du serveur Controller (`https://…`), ou
  renseignez l'écran **Général** : le serveur MCP donne son interface web (`/ui`) aux clients
  sans jeton valide, pour que l'utilisateur sache où créer un
  jeton MCP personnel ;
- pour que les hôtes MCP se connectent par le navigateur plutôt qu'avec un jeton MCP personnel,
  réglez `SECREVIEW_MCP_OAUTH_ENABLED` et `SECREVIEW_MCP_URL` (URL publique de `/mcp`), avec
  `SECREVIEW_CONTROLLER_URL` en `https` (voir [Connexion OAuth des clients MCP](../mcp-oauth.md)) ;
- réglez `SECREVIEW_FORWARDED_ALLOW_IPS` sur la plage d'adresses des pods de l'ingress
  controller : sinon tous les clients partagent leur adresse pour la limitation des connexions,
  la limite de débit et le journal d'audit.

La NetworkPolicy du serveur Controller laisse entrer l'ingress controller du namespace `ingress-nginx` :
adaptez son label au vôtre. Les commandes d'administration s'exécutent dans le pod du
serveur Controller :

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list
```

## Mise à jour OSV

Pour la [mise à jour quotidienne des avis OSV](../../review/analysis/dependencies.md#mise-a-jour-automatique-par-le-serveur-controller),
décommentez `SECREVIEW_OSV_AUTO_UPDATE` (et au besoin `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
et `NO_PROXY`, dans le Secret `secreview-controller` si le proxy contient des identifiants) sur
le conteneur `controller`, et autorisez sa sortie vers `osv-vulnerabilities.storage.googleapis.com` (`SECREVIEW_OSV_URL`),
votre miroir ou le proxy si une NetworkPolicy d'egress s'applique. Le serveur MCP
n'a besoin d'aucune sortie. La documentation Swagger de l'API REST (`/api/docs`) reste
désactivée tant que vous ne décommentez pas `SECREVIEW_SWAGGER_ENABLED`.

## Plusieurs réplicas

!!! warning "Plusieurs réplicas du serveur MCP"
    Les sessions MCP (transport streamable HTTP) sont gardées en mémoire par le pod qui les a
    ouvertes. Avant d'augmenter `replicas`, configurez l'Ingress pour envoyer toutes les
    requêtes d'une session au même pod (affinité sur l'en-tête `Mcp-Session-Id`, ou à défaut
    affinité par cookie ou par adresse). Le serveur Controller peut, lui, avoir plusieurs réplicas :
    leurs migrations s'attendent (verrou consultatif PostgreSQL), et `SECREVIEW_SECRET_KEY` leur
    permet de partager les sessions web.
