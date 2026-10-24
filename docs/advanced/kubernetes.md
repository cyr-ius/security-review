# Kubernetes

The
[`examples/kubernetes/security-review.yaml`](https://github.com/cyr-ius/security-review-mcp/blob/master/examples/kubernetes/security-review.yaml)
example deploys both processes on an existing PostgreSQL database:

```bash
kubectl create namespace secreview
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL='postgresql+psycopg2://secreview:<password>@<host>:5432/secreview'
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f examples/kubernetes/security-review.yaml
kubectl -n secreview exec deploy/secreview-controller -c controller -- security-review-controller user reset-password admin   # initial admin password
```

It contains:

- a **`secreview-controller` Deployment** (one replica, `Recreate` strategy) whose init
  container runs `security-review-controller db upgrade` at every deployment;
- a **`secreview-mcp` Deployment**, which only checks the schema;
- the **`secreview-controller` Secret**, created by hand (see below), with
  `SECREVIEW_SECRET_KEY`: without it, the controller draws a random session secret at every
  start, so the web sessions would end at every restart and would not be shared by the
  replicas (see [Login and sessions](../usage/web-interface.md#login-and-sessions));
- one Service per process, `readiness` and `liveness` probes on `/healthz`, non-root
  containers with a read-only file system, without any Linux capability;
- a **NetworkPolicy** that limits access to the controller to the pods of the namespace and to
  the ingress controller (adapt its label).

The two Secrets are not in the example, so that `kubectl apply` never replaces their values. To
declare them as manifests rather than with `kubectl create secret` (GitOps), use `kind: Secret`:

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

Replace the image (`registry.example.com/security-review-mcp:pg`) with yours, built with the
`postgres` extra. Expose the `secreview-mcp` Service to the agents and to the CI through an
Ingress with TLS. Keep the controller internal (`kubectl port-forward`, VPN or Ingress
restricted to administrators). Behind the Ingress, set `SECREVIEW_FORWARDED_ALLOW_IPS` (commented
in the ConfigMap) to the address range of the ingress controller pods: otherwise every client
shares their address for the login throttling and the enrollment limits. Administration commands run in its pod:

```bash
kubectl -n secreview exec deploy/secreview-controller -c controller -- \
    security-review-controller token list
```

For the [daily update of the OSV advisories](dependencies.md#automatic-update-by-the-controller),
uncomment `SECREVIEW_OSV_AUTO_UPDATE` (and if needed `SECREVIEW_OSV_ECOSYSTEMS`, `HTTPS_PROXY`
and `NO_PROXY`, in the `secreview-controller` Secret if the proxy holds credentials) on the
`controller` container, and allow its egress to osv.dev or your mirror (or the proxy) if an
egress NetworkPolicy applies. The MCP server needs no egress. The Swagger documentation of the
REST API (`/api/docs`) stays disabled unless you uncomment `SECREVIEW_SWAGGER_ENABLED`.

!!! warning "Several replicas of the MCP server"
    MCP sessions (streamable HTTP transport) are kept in memory by the pod that opened them.
    Before raising `replicas`, configure the Ingress to send every request of a session to the
    same pod (affinity on the `Mcp-Session-Id` header, or failing that cookie or address
    affinity). The controller can have several replicas, provided the migration is done by a
    single task (`SECREVIEW_DB_AUTO_UPGRADE=false` on the replicas).
