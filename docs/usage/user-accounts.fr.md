# Comptes utilisateurs

Un compte associe un **identifiant** (lettres, chiffres et `. _ @ -`, 64 caractères au plus), un
**type** et des **groupes** : les rôles de ses groupes donnent ses
[permissions](../advanced/access-control.md#ce-quun-utilisateur-peut-faire). Les machines
utilisent des [jetons](tokens.md).

| Type (`auth_source`) | Connexion | Création |
|---|---|---|
| **Local** (`local`) | Identifiant et mot de passe | Par un administrateur, ou le compte `admin` initial |
| **OIDC** (`oidc`) | [Fournisseur d'identité](../advanced/sso.md#comptes-oidc), sans mot de passe | Par un administrateur, ou à la première connexion si `SECREVIEW_OIDC_AUTO_CREATE_USERS=true` |

Un compte OIDC rejoint aussi, à chaque connexion, les groupes ouverts au OIDC nommés par son claim
des groupes (voir [comptes OIDC](../advanced/sso.md#comptes-oidc)). Les comptes se gèrent dans
l'écran **Utilisateurs**, par l'API REST `/api/v1/users` (permission `users.manage`) ou par la
[CLI](../reference/cli.md#security-review-controller) :

```bash
security-review-controller user create alice --group shop-triagers
# {"id": 2, "username": "alice", "auth_source": "local", "groups": [{"group_id": 3, "name": "shop-triagers", "source": "local"}], "permissions": {…}, …, "password": "q3V…"}
printf '%s\n' "$PASSWORD" | security-review-controller user create bob --password-stdin
security-review-controller user create carol@example.com --sso   # groupes OIDC seulement
security-review-controller user list
security-review-controller user set-groups alice --group readers --group auditors
security-review-controller user set-groups alice --group administrators   # créé s'il manque
security-review-controller user reset-password alice   # compte local : nouveau mot de passe, sessions fermées
security-review-controller user delete alice
security-review-controller group list    # groupes, leurs rôles et leurs membres
```

Par l'API, un compte OIDC se crée avec `"auth_source": "oidc"`, sans `password` ; `group_ids`
liste ses groupes :

```bash
curl -X POST https://secreview.example.com/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "carol@example.com", "auth_source": "oidc", "group_ids": [4]}'
```

Pour un compte local, sans `--password-stdin` (ou sans mot de passe dans l'interface), un mot de
passe aléatoire de 24 caractères est généré et affiché **une seule fois**. Un mot de passe choisi
respecte la **politique de mot de passe** : 12 à 256 caractères, avec au moins une minuscule, une
majuscule, un chiffre et un caractère qui n'est ni une lettre ni un chiffre. Les écrans affichent
ces règles sous le champ et cochent chacune pendant la saisie, et **Mon compte** indique aussitôt
si la confirmation correspond. La politique s'applique aux nouveaux mots de passe : un mot de passe
défini avant reste valable jusqu'à son changement. Un compte OIDC n'a jamais de mot de passe : la connexion par
identifiant et mot de passe, la réinitialisation et **Mon compte** le refusent.

!!! warning "Authentification requise pour la Web UI"
    L'API de l'interface refuse les requêtes avec le statut `503` tant qu'aucun utilisateur ni
    jeton n'existe ; la mire de connexion reste affichée et indique que l'authentification doit
    être configurée. `security-review-controller serve` crée le
    [premier administrateur](../advanced/controller.md#premier-administrateur) à son premier démarrage : cela n'arrive donc
    qu'avant ; un compte peut aussi être créé avec `security-review-controller user create`. Cette restriction concerne
    la Web UI ; l'authentification MCP reste indépendante (un compte utilisateur n'ouvre jamais
    `/mcp`). Avec la [connexion OIDC](../advanced/sso.md), l'API demande une connexion
    (`401`) même sans utilisateur ni jeton en base.

Le [premier administrateur](../advanced/controller.md#premier-administrateur), le
[mot de passe perdu](../advanced/controller.md#mot-de-passe-perdu) et la
[connexion et les sessions](../advanced/controller.md#connexion-et-sessions) sont décrits dans
[Contrôleur](../advanced/controller.md), avec la sécurité de l'interface. Les variables de
l'interface sont dans la [Configuration](../reference/configuration.md#interface-web-et-sessions).
