# Comptes utilisateurs

Un compte utilisateur permet à une **personne** d'ouvrir l'interface web. Ce qu'il peut faire
vient uniquement de ses **groupes** : leurs rôles donnent ses
[permissions](access-control.md#ce-quun-utilisateur-peut-faire). Les machines
utilisent des [jetons](tokens.md).

La ligne de commande, l'API REST et les réglages sont dans
[Gérer les comptes](../advanced/architecture/controller.md#gerer-les-comptes).

| Type | Connexion | Création |
|---|---|---|
| **Local** | Identifiant et mot de passe | Par un administrateur, dans l'écran **Utilisateurs** |
| **OIDC** | Connexion d'entreprise ([fournisseur d'identité](sso.md#comptes-oidc)), sans mot de passe | Par un administrateur, ou à la première connexion quand le serveur le permet |

Un compte OIDC rejoint aussi, à chaque connexion, les groupes que nomme son fournisseur
d'identité (voir [groupes du fournisseur d'identité](sso.md#groupes-du-fournisseur-didentite)).

## Mot de passe

Un mot de passe défini par quelqu'un d'autre (nouveau compte local, réinitialisation par un
administrateur) **se change à la première connexion** : l'interface ouvre **Mon compte** avant
toute autre chose.

Un mot de passe choisi respecte la **politique de mot de passe** : au moins 12 caractères, avec
une minuscule, une majuscule, un chiffre et un caractère spécial. Les écrans cochent chaque règle
pendant la saisie. Un mot de passe généré par l'interface n'est affiché **qu'une fois**.

Un compte OIDC n'a pas de mot de passe : il est géré par le fournisseur d'identité.

## Sessions

- Une session dure 8 heures par défaut. À son terme, la fenêtre **Session expirée** s'ouvre :
  **Se reconnecter** vous ramène à la même page.
- **Se déconnecter** ferme les sessions du compte dans tous les onglets et navigateurs ; un
  nouveau mot de passe ou la suppression du compte aussi.
- Un changement de groupes ou de rôles s'applique aussitôt, sans se reconnecter.

## Points d'attention

- **Un mot de passe perdu** est remplacé par un administrateur ; le tout premier administrateur
  est créé au premier démarrage du serveur Controller
  ([premier administrateur](../advanced/architecture/controller.md#premier-administrateur)).
- **Un compte OIDC supprimé n'est pas recréé** à sa prochaine connexion, tant qu'un
  administrateur n'a pas cliqué sur **Autoriser à nouveau** dans **Utilisateurs**.
- **Le dernier administrateur** (détenteur de `users.manage`) ne peut être ni supprimé ni perdre
  cette permission.
- **Un compte utilisateur ne connecte jamais un agent** : l'agent utilise un
  [jeton personnel](tokens.md#jetons-mcp-et-ci-personnels).
