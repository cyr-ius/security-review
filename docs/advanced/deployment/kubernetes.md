# Kubernetes

Two manifests deploy everything in the `secreview` namespace:
[`examples/kubernetes/postgres.yaml`](https://github.com/cyr-ius/security-review/blob/{{ release_tag }}/examples/kubernetes/postgres.yaml)
(PostgreSQL, official image) and
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review/blob/{{ release_tag }}/examples/kubernetes/security-review.yaml)
(controller and MCP server, published image `ghcr.io/cyr-ius/security-review:latest`).

## Deployment

The block that deploys everything, with the PostgreSQL of `postgres.yaml`, is in
[Deploying the server](../../getting-started/deploy.md#with-kubernetes).

With an existing PostgreSQL: a managed database (Amazon RDS, Azure Database for PostgreSQL, Google Cloud SQL...) or an
operator (CloudNativePG...) holding an empty `secreview` database owned by a `secreview`
role. Replace `<password>` and `<host>`; add `?sslmode=verify-full` to the URL when the
server offers TLS.

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

## Content of the manifests

`postgres.yaml` contains a **`secreview-postgres` StatefulSet** (official image
`postgres:18-alpine`, one instance, 10 GiB volume, non-root container with a read-only file
system), its Service and a **NetworkPolicy** that only lets the pods of security-review-mcp
reach the port `5432`. For production, prefer a managed database or an operator, which handle
replication, backups and upgrades.

`security-review.yaml` contains:

- a **`secreview-controller` Deployment** (one replica, `Recreate` strategy), which migrates
  the schema when it starts (a `startup` probe gives it up to 10 minutes);
- a **`secreview-mcp` Deployment**, which only checks the schema when it starts;
- a **`secreview-config` ConfigMap** shared by both processes;
- one Service per process, `readiness` and `liveness` probes on `/healthz`, non-root
  containers with a read-only file system, without any Linux capability;
- a **NetworkPolicy** that limits access to the controller to the pods of the namespace and to
  the ingress controller (adapt its label).

The controller also reads the **`secreview-controller` Secret**, created by hand (see
[Secrets](#secrets)), with `SECREVIEW_SECRET_KEY`: without it, the controller draws a random
session secret at every start, so the web sessions would end at every restart and would not be
shared by the replicas (see [Login and sessions](../architecture/controller.md#login-and-sessions)).

Content of the manifests of version `{{ release_tag }}`, applied by these commands:

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

The manifest uses the published image `ghcr.io/cyr-ius/security-review:latest`, which
contains the PostgreSQL driver: pin a version (`X.Y.Z`) in production. The manifests contain
no Ingress: expose each Service through its own Ingress with TLS.

| Service | Reached by | Ingress |
|---|---|---|
| `secreview-mcp` | the agents (MCP on `/mcp`) | to every developer workstation |
| `secreview-controller` | the people (web interface `/ui`, personal MCP and CI tokens) and the CI (`security-review-ci` calls `/api/v1/ci`) | to the developers and to the CI runners; `kubectl port-forward` is enough for a first test |

Then, in the ConfigMap:

- set `SECREVIEW_CONTROLLER_URL` to the public root URL of the controller (`https://…`), or
  fill in the **General** screen: the MCP server gives its web interface (`/ui`) to the clients
  without a valid token, so that the user knows where to create
  a personal MCP token;
- set `SECREVIEW_FORWARDED_ALLOW_IPS` to the address range of the ingress controller pods:
  otherwise every client shares their address for the login throttling, the rate limit and the
  audit log.

The NetworkPolicy of the controller lets in the ingress controller of the `ingress-nginx`
namespace: adapt its label to yours. Administration commands run in the pod of the controller:

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list
```

## OSV update

For the [daily update of the OSV advisories](../../review/analysis/dependencies.md#automatic-update-by-the-controller),
uncomment `SECREVIEW_OSV_AUTO_UPDATE` (and if needed `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
and `NO_PROXY`, in the `secreview-controller` Secret if the proxy holds credentials) on the
`controller` container, and allow its egress to `osv-vulnerabilities.storage.googleapis.com` (`SECREVIEW_OSV_URL`),
your mirror or the proxy if an
egress NetworkPolicy applies. The MCP server needs no egress. The Swagger documentation of the
REST API (`/api/docs`) stays disabled unless you uncomment `SECREVIEW_SWAGGER_ENABLED`.

## Several replicas

!!! warning "Several replicas of the MCP server"
    MCP sessions (streamable HTTP transport) are kept in memory by the pod that opened them.
    Before raising `replicas`, configure the Ingress to send every request of a session to the
    same pod (affinity on the `Mcp-Session-Id` header, or failing that cookie or address
    affinity). The controller can have several replicas: their migrations wait for each other
    (PostgreSQL advisory lock), and `SECREVIEW_SECRET_KEY` lets them share the web sessions.
