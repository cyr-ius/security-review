# Deploying the server

This page sets up the **shared mode (HTTP)** for a team: the controller (web interface,
administration) and the MCP server (used by the agents and the CI), on the same database. See
[two services, two roles](../index.md#two-services-two-roles).

At the end, you have:

- a web interface where people read and triage the reports;
- an `/mcp` endpoint, protected by tokens, that the hosts of the developers connect to;
- an `admin` account to manage the users, the tokens and the rules.

Two ways, each in a single block to copy and paste:

- [with Docker Compose](#with-docker-compose) (recommended): one server, PostgreSQL included;
- [with Kubernetes](#with-kubernetes): a cluster, PostgreSQL included or existing.

Without containers, all-in-one on one Linux server: see
[Manual installation (without containers)](../advanced/manual-install.md).

## With Docker Compose

One `docker-compose.yml` file starts everything with the published image: PostgreSQL, the
migration of the schema, the controller and the MCP server. Copy and paste the block in an
empty folder: it downloads the file, generates the passwords in `.env`, starts the services,
then gives the password of the `admin` account and a token (each shown once):

```bash
mkdir security-review-mcp && cd security-review-mcp
curl -fsSLO https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/docker/docker-compose.yml
(umask 077 && printf 'POSTGRES_PASSWORD=%s\nSECREVIEW_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env)
docker compose up -d --wait
docker compose exec controller security-review-controller user reset-password admin   # initial admin password
docker compose exec controller security-review-controller token create --label alice   # token of an agent
```

The web interface answers on `http://127.0.0.1:8080/ui/`, the MCP endpoint on
`http://127.0.0.1:8000/mcp`. Sign in with the `admin` account, choose your own password in
**My account**, then create an account for each person in the **Users** screen (see
[User accounts](../usage/web-interface.md#user-accounts)).

Both ports are only published on `127.0.0.1`: to open them to the team, add TLS and set
`DOCKER_PUBLISH_ADDRESS` (see
[Docker Compose with PostgreSQL](../advanced/docker.md#docker-compose-with-postgresql)).

!!! warning "The CLI is the only way to obtain the initial password"
    It is not defined by any variable, nor does it ever appear in the logs: run
    `user reset-password admin` inside the container, and treat the output as a secret.
    If you lose it, simply run the command again (the previous password will be invalidated immediately).

**More information:** see [Docker](../advanced/docker.md) in the **Advanced** section (opening to
the team, TLS, OSV update, backups, PostgreSQL upgrade, without Docker Compose).

## With Kubernetes

Copy and paste the whole block: it deploys PostgreSQL (official image), the controller and the
MCP server (published image) in the `secreview` namespace, then gives the first administrator
password and a token. An init container migrates the schema.

```bash
kubectl create namespace secreview

# 1. PostgreSQL (official image): one password, in the Secret of the database and in the URL
PGPASSWORD="$(openssl rand -hex 24)"
kubectl -n secreview create secret generic secreview-postgres \
    --from-literal=POSTGRES_PASSWORD="$PGPASSWORD"
kubectl -n secreview create secret generic secreview-db \
    --from-literal=SECREVIEW_DATABASE_URL="postgresql+psycopg2://secreview:${PGPASSWORD}@secreview-postgres:5432/secreview"
unset PGPASSWORD
kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/kubernetes/postgres.yaml
kubectl -n secreview rollout status statefulset/secreview-postgres

# 2. security-review-mcp: session secret, controller and MCP server
kubectl -n secreview create secret generic secreview-controller \
    --from-literal=SECREVIEW_SECRET_KEY="$(openssl rand -hex 32)"
kubectl -n secreview apply -f https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/kubernetes/security-review.yaml
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

The controller is not exposed outside the cluster: you open the web interface from your
workstation with the last command of the block (`port-forward`), which stays active as long as
the terminal is open.

For the developers and the CI to reach the MCP server, expose the `secreview-mcp` Service
through an Ingress with TLS. Then set `SECREVIEW_FORWARDED_ALLOW_IPS` (commented in the
ConfigMap of the manifest) to the address range of the ingress controller pods: without it,
every client seems to come from the same address, the one of the Ingress.

**More information:** see [Kubernetes](../advanced/kubernetes.md) in the **Advanced** section
(existing PostgreSQL, content of the manifests, Secrets, exposure, OSV update, several replicas).

## Next step

[Connect the host](host.md) of each developer to the MCP server. To go further:
[tokens, enrollment and TLS](../advanced/http.md), [OIDC login](../advanced/sso.md).
