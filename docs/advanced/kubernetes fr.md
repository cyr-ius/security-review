# Kubernetes

L'exemple
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/master/examples/kubernetes/security-review.yaml)
déploie les deux processus sur une base PostgreSQL existante :

```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f examples/kubernetes/security-review.yaml
kubectl -n secreview exec deploy/secreview-controller -c controller -- security-review-controller user reset-password admin   # mot de passe admin initial
```

Il contient :

- un **Deployment `secreview-controller`** (une réplique, stratégie `Recreate`) dont l'init
  container lance `security-review-controller db upgrade` à chaque déploiement ;
- un **Deployment `secreview-mcp`**, qui vérifie seulement le schéma ;
- le **Secret `secreview-controller`**, créé à la main (voir ci-dessous), avec
  `SECREVIEW_SECRET_KEY` : sans lui, le contrôleur tire un secret de session aléatoire à
  chaque démarrage, les sessions web prendraient donc fin à chaque redémarrage et ne seraient
  pas partagées entre réplicas (voir
  [Connexion et sessions](../usage/web-interface.md#connexion-et-sessions)) ;
- un Service par processus, des sondes `readiness` et `liveness` sur `/healthz`, des
  conteneurs non root en système de fichiers en lecture seule, sans capacité Linux ;
- une **NetworkPolicy** qui limite l'accès au contrôleur aux pods du namespace et à
  l'ingress controller (adaptez son label).

Les deux Secrets ne sont pas dans l'exemple, pour que `kubectl apply` ne remplace jamais leurs
valeurs. Pour les déclarer en manifestes plutôt qu'avec `kubectl create secret` (GitOps),
utilisez `kind: Secret` :

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secreview-db
  namespace: secreview
type: Opaque
stringData:
  SECREVIEW_DATABASE_URL: postgresql+psycopg2://secreview:<password>@<host>:5432/secreview
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

Remplacez l'image (`registry.example.com/security-review-mcp:pg`) par la vôtre, construite avec
l'extra `postgres`. Exposez le Service `secreview-mcp` aux agents et à la CI par un Ingress avec
TLS. Gardez le contrôleur interne (`kubectl port-forward`, VPN ou Ingress restreint aux
administrateurs). Derrière l'Ingress, réglez `SECREVIEW_FORWARDED_ALLOW_IPS` (en commentaire dans
la ConfigMap) sur la plage d'adresses des pods de l'ingress controller : sinon tous les clients
partagent leur adresse pour la limitation des connexions et les limites d'enrôlement. Les
commandes d'administration s'exécutent dans son pod :

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list
```

Pour la [mise à jour quotidienne des avis OSV](dependencies.md#mise-a-jour-automatique-par-le-controleur),
décommentez `SECREVIEW_OSV_AUTO_UPDATE` (et au besoin `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
et `NO_PROXY`, dans le Secret `secreview-controller` si le proxy contient des identifiants) sur
le conteneur `controller`, et autorisez sa sortie vers osv.dev ou votre miroir (ou le proxy) si une NetworkPolicy d'egress s'applique. Le serveur MCP
n'a besoin d'aucune sortie. La documentation Swagger de l'API REST (`/api/docs`) reste
désactivée tant que vous ne décommentez pas `SECREVIEW_SWAGGER_ENABLED`.

!!! warning "Plusieurs réplicas du serveur MCP"
    Les sessions MCP (transport streamable HTTP) sont gardées en mémoire par le pod qui les a
    ouvertes. Avant d'augmenter `replicas`, configurez l'Ingress pour envoyer toutes les
    requêtes d'une session au même pod (affinité sur l'en-tête `Mcp-Session-Id`, ou à défaut
    affinité par cookie ou par adresse). Le contrôleur peut, lui, avoir plusieurs réplicas, à
    condition que la migration soit faite par une seule tâche (`SECREVIEW_DB_AUTO_UPGRADE=false`
    sur les réplicas).
