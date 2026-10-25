# Kubernetes

Two manifests deploy everything in the `secreview` namespace:
[`examples/kubernetes/postgres.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/{{ release_tag }}/examples/kubernetes/postgres.yaml)
(PostgreSQL, official image) and
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/{{ release_tag }}/examples/kubernetes/security-review.yaml)
(controller and MCP server, published image `ghcr.io/cyr-ius/security-review-mcp:latest`).

## Deployment

=== "With PostgreSQL (official image)"

    Copy and paste the whole block: it creates the database, its password and the Secrets,
    then starts security-review-mcp and gives the first administrator password.

    ```bash
    kubectl create namespace secreview

    # 1. PostgreSQL (official image): one password, in the Secret of the database and in the URL
    PGPASSWORD="$(openssl rand -hex 24)"
    kubectl -n secreview create secret generic secreview-postgres \
        --from-literal=POSTGRES_PASSWORD="$PGPASSWORD"
    kubectl -n secreview create secret generic secreview-db \
        --from-literal=SECREVIEW_DATABASE_URL="postgresql+psycopg2://secreview:${PGPASSWORD}@secreview-postgres:5432/secreview"
    unset PGPASSWORD
    kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review-mcp/{{ release_tag }}/examples/kubernetes/postgres.yaml
    kubectl -n secreview rollout status statefulset/secreview-postgres

    # 2. security-review-mcp: session secret, controller and MCP server
    kubectl -n secreview create secret generic secreview-controller \
        --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
    kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review-mcp/{{ release_tag }}/examples/kubernetes/security-review.yaml
    kubectl -n secreview rollout status deploy/secreview-controller
    kubectl -n secreview rollout status deploy/secreview-mcp

    # 3. First administrator and token of an agent (each secret is shown once)
    kubectl -n secreview exec deploy/secreview-controller -c controller -- \
        security-review-controller user reset-password admin
    kubectl -n secreview exec deploy/secreview-controller -c controller -- \
        security-review-controller token create --label alice

    # 4. Web interface on http://127.0.0.1:8080/ui/
    kubectl -n secreview port-forward svc/secreview-controller 8080:80
    ```

=== "With an existing PostgreSQL"

    A managed database (Amazon RDS, Azure Database for PostgreSQL, Google Cloud SQL...) or an
    operator (CloudNativePG...) holding an empty `secreview` database owned by a `secreview`
    role. Replace `<password>` and `<host>`; add `?sslmode=verify-full` to the URL when the
    server offers TLS.

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

## Content of the manifests

`postgres.yaml` contains a **`secreview-postgres` StatefulSet** (official image
`postgres:18-alpine`, one instance, 10 GiB volume, non-root container with a read-only file
system), its Service and a **NetworkPolicy** that only lets the pods of security-review-mcp
reach the port `5432`. For production, prefer a managed database or an operator, which handle
replication, backups and upgrades.

`security-review.yaml` contains:

- a **`secreview-controller` Deployment** (one replica, `Recreate` strategy) whose init
  container runs `security-review-controller db upgrade` at every deployment;
- a **`secreview-mcp` Deployment**, which only checks the schema;
- the **`secreview-controller` Secret**, created by hand (see [Secrets](#secrets)), with
  `SECREVIEW_SECRET_KEY`: without it, the controller draws a random session secret at every
  start, so the web sessions would end at every restart and would not be shared by the
  replicas (see [Login and sessions](../usage/web-interface.md#login-and-sessions));
- one Service per process, `readiness` and `liveness` probes on `/healthz`, non-root
  containers with a read-only file system, without any Linux capability;
- a **NetworkPolicy** that limits access to the controller to the pods of the namespace and to
  the ingress controller (adapt its label).

Content of the manifests of version `{{ release_tag }}`, applied by the commands above:

=== "postgres.yaml"

    ```yaml
    --8<-- "kubernetes/postgres.yaml"
    ```

=== "security-review.yaml"

    ```yaml
    --8<-- "kubernetes/security-review.yaml"
    ```

## Secrets

The Secrets (`secreview-postgres`, `secreview-db`, `secreview-controller`) are not in the
examples, so that `kubectl apply` never replaces their values. The password of
`secreview-postgres` and the one of the URL of `secreview-db` must be the same. To declare them as manifests rather than with `kubectl create secret` (GitOps), use `kind: Secret`:

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
  # openssl rand -hex 32 (at least 32 characters, never changed between deployments)
  SECREVIEW_SECRET_KEY: <64 hexadecimal characters>
  # Proxy holding credentials (OSV download, OIDC), optional
  # HTTPS_PROXY: http://user:<password>@proxy.example.com:3128
```

`stringData` takes the values in clear; Kubernetes stores them base64-encoded in `data`. Never
commit this file with real values: encrypt it (Sealed Secrets, SOPS) or let an operator such as
External Secrets create it from your vault. The pods read the Secrets at start-up: after a
change, restart them (`kubectl -n secreview rollout restart deploy/secreview-controller`).
Changing `SECREVIEW_SECRET_KEY` ends every web session.

## Image, exposure and administration

The manifest uses the published image `ghcr.io/cyr-ius/security-review-mcp:latest`, which
contains the PostgreSQL driver: pin a version (`X.Y.Z`) in production. Expose the `secreview-mcp` Service to the agents and to the CI through an
Ingress with TLS. Keep the controller internal (`kubectl port-forward`, VPN or Ingress
restricted to administrators). Behind the Ingress, set `SECREVIEW_FORWARDED_ALLOW_IPS` (commented
in the ConfigMap) to the address range of the ingress controller pods: otherwise every client
shares their address for the login throttling and the enrollment limits. Administration commands run in its pod:

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list
```

## OSV update

For the [daily update of the OSV advisories](dependencies.md#automatic-update-by-the-controller),
uncomment `SECREVIEW_OSV_AUTO_UPDATE` (and if needed `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
and `NO_PROXY`, in the `secreview-controller` Secret if the proxy holds credentials) on the
`controller` container, and allow its egress to osv.dev or your mirror (or the proxy) if an
egress NetworkPolicy applies. The MCP server needs no egress. The Swagger documentation of the
REST API (`/api/docs`) stays disabled unless you uncomment `SECREVIEW_SWAGGER_ENABLED`.

## Several replicas

!!! warning "Several replicas of the MCP server"
    MCP sessions (streamable HTTP transport) are kept in memory by the pod that opened them.
    Before raising `replicas`, configure the Ingress to send every request of a session to the
    same pod (affinity on the `Mcp-Session-Id` header, or failing that cookie or address
    affinity). The controller can have several replicas, provided the migration is done by a
    single task (`SECREVIEW_DB_AUTO_UPGRADE=false` on the replicas).
