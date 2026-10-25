# User accounts

An account ties a **user name** (letters, digits and `. _ @ -`, 64 characters at most), a
**type** and **groups**: the roles of its groups give its
[permissions](../advanced/access-control.md#what-a-user-may-do). The machines use
[tokens](tokens.md) instead.

| Type (`auth_source`) | Login | Creation |
|---|---|---|
| **Local** (`local`) | User name and password | By an administrator, or the initial `admin` account |
| **OIDC** (`oidc`) | [Identity provider](../advanced/sso.md#oidc-accounts), no password | By an administrator, or at the first login if `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

An OIDC account also joins, at each login, the groups open to OIDC named by its groups claim (see
[OIDC accounts](../advanced/sso.md#oidc-accounts)). Accounts are managed in the **Users** screen,
through the `/api/v1/users` REST API (`users.manage` permission) or with the
[CLI](../reference/cli.md#security-review-controller):

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # OIDC groups only
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # created if missing
security-review-controller user reset-password alice   # local account: new password, sessions closed
security-review-controller user delete alice
security-review-controller group list    # groups, their roles and members
```

Through the API, an OIDC account is created with `"auth_source": "oidc"`, without `password`;
`group_ids` lists its groups:

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4]}'
```

For a local account, without `--password-stdin` (or without a password in the interface), a
random 24-character password is generated and shown **only once**. A chosen password follows
the **password policy**: 12 to 256 characters, with at least a lowercase letter, an uppercase
letter, a digit and a character that is neither a letter nor a digit. The screens list these
rules under the field and tick each one while the password is typed, and **My account** says at
once whether the confirmation matches. The policy applies to new passwords: a password set
before keeps working until it is changed. An OIDC account never has a password: the user name and password login, the
reset and **My account** refuse it.

!!! warning "Authentication required for the web UI"
    The API of the interface refuses the requests with status `503` while no user and no token
    exist; the login form stays displayed and says that authentication must be configured.
    `security-review-controller serve` creates the [first administrator](../advanced/controller.md#first-administrator)
    at its first start, so this only happens before it; an account can also be created with
    `security-review-controller user create`. This restriction concerns the web
    UI; MCP authentication stays independent (a user account never opens `/mcp`). With the
    [OIDC login](../advanced/sso.md), the API asks for a login (`401`) even without any
    user or token in the database.

The [first administrator](../advanced/controller.md#first-administrator), the
[lost password](../advanced/controller.md#lost-password) and the
[login and sessions](../advanced/controller.md#login-and-sessions) are described in
[Controller](../advanced/controller.md), with the security of the interface. The variables of
the interface are in the [Configuration](../reference/configuration.md#web-interface-and-sessions).
