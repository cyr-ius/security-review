# Deploying the server

This page sets up the **shared mode (HTTP)** for a team: the Controller server (web interface,
administration, pipelines) and the MCP server (used by the agents), on the same database. See
[three services, three roles](../services.md).

```mermaid
flowchart LR
    dev(["Developer"]) --> agent
    subgraph ws["Developer workstation"]
        agent["AI assistant<br/>VS Code, Claude"]
    end
    analyst(["Security analyst<br/>(browser)"])
    ci(["CI/CD pipeline<br/>security-review-ci"])
    subgraph srv["Server or cluster (containers)"]
        mcp["MCP server container<br/>security-review-mcp"]
        ctl["Controller container<br/>security-review-controller<br/>web interface, REST API"]
        pg[("PostgreSQL container<br/>reports, rules, tokens")]
    end
    agent -- "HTTPS /mcp<br/>MCP token" --> mcp
    analyst -- "HTTPS /ui<br/>user account" --> ctl
    ci -- "HTTPS /api/v1/ci<br/>ci token" --> ctl
    mcp --> pg
    ctl --> pg
```

At the end, you have:

- a web interface where people read and triage the reports;
- an `/mcp` endpoint, protected by tokens, that the hosts of the developers connect to;
- an `admin` account to manage the users, the tokens and the rules.

Without containers, all-in-one on one Linux server: see Advanced section
[Manual installation (without containers)](../advanced/deployment/manual-install.md).

## With Docker Compose

The `docker-compose.yml` file starts a PostgreSQL database,
the Controller server, and the MCP server.

Copy and paste this code into an empty folder.
This will download the `docker-compose.yml` file, generate secrets in a `.env` file, start the services,
display the password for the `admin` account, and create a token to be placed in the `mcp.json` file within Alice's IDE.

```bash
mkdir security-review-mcp && cd security-review-mcp
curl -fsSLO https://raw.githubusercontent.com/cyr-ius/security-review/{{ release_tag }}/examples/docker/docker-compose.yml
(umask 077 && printf 'POSTGRES_PASSWORD=%s\nSECREVIEW_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env)
docker compose up -d --wait
docker compose exec controller security-review-controller user reset-password admin   # initial admin password
docker compose exec controller security-review-controller token create --label alice   # token of an agent
```

The web interface is accessible at `http://127.0.0.1:8080/ui/`. Log in using the `admin` account,
and change the password upon your first login.

The MCP server is located at `http://127.0.0.1:8000/mcp`.

!!! warning "The CLI is the only way to obtain the initial password"
    It is not defined by any variable, nor does it ever appear in the logs: run
    `user reset-password admin` inside the container, and treat the output as a secret.
    If you lose it, simply run the command again (the previous password will be invalidated immediately).

**More information:** see [Docker](../advanced/deployment/docker.md) in the **Advanced** section (opening to
the team, TLS, OSV update, without Docker Compose), and [Database](../advanced/database.md) for backups
and the PostgreSQL upgrade.

## With Kubernetes

Copy and paste the whole block: it deploys PostgreSQL (official image), the Controller server and the
MCP server (published image) in the `secreview` namespace, then gives the first administrator
password and a token. The Controller server migrates the schema when it starts.

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

# 2. security-review-mcp: session secret, Controller server and MCP server
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

The manifests expose nothing outside the cluster: for a first test, you open the web interface
from your workstation with the last command of the block (`port-forward`), which stays active
as long as the terminal is open.

For the team, expose each Service through an Ingress with TLS: `secreview-mcp` for the agents,
`secreview-controller` for the developers (web interface, personal MCP tokens) and for the CI
(`security-review-ci` calls the Controller server). Then set, in the ConfigMap of the manifest,
`SECREVIEW_PUBLIC_URL` (public root URL of the Controller server) and `SECREVIEW_FORWARDED_ALLOW_IPS` (address
range of the ingress controller pods: without it, every client seems to come from the same
address, the one of the Ingress). To let the MCP hosts sign in through the browser instead of a
personal token, see [OAuth login of MCP clients](../advanced/mcp-oauth.md): with one Ingress per
Service, the OAuth paths need no extra rule.

**More information:** see [Kubernetes](../advanced/deployment/kubernetes.md) in the **Advanced** section
(existing PostgreSQL, content of the manifests, Secrets, exposure, OSV update, several replicas).

## Next step

[Connect the host](host.md) of each developer to the MCP server. To go further:
[tokens](../advanced/bearer-tokens.md), [TLS](../advanced/tls.md), [OIDC login](../usage/sso.md).
