# Jetons

Les **jetons** sont destinés aux machines : agents MCP, pipelines CI/CD, Prometheus et scripts
d'administration. Les **personnes** se connectent avec un [compte utilisateur](user-accounts.md),
seul moyen d'ouvrir l'interface web, avec les droits de ses groupes
([Rôles, groupes et permissions](access-control.md)). Il n'existe pas de jeton de
lecture ou de triage : pour qu'une personne lise ou trie, ajoutez son compte à un groupe.

La ligne de commande, l'API REST et les limites sont dans [Jetons Bearer](../advanced/bearer-tokens.md).

## Rôles d'un jeton

Chaque jeton porte un rôle fixe, qui détermine ce qu'il atteint.

| Rôle | Pour | Créé |
|---|---|---|
| `mcp` | Un agent MCP (Claude Code, Copilot, Codex...) | Écran **Jetons**, ou jeton personnel |
| `ci` | Le client de pipeline [`security-review-ci`](../advanced/ci.md) : gate, SARIF, tendance, scans | Écran **Jetons**, toujours pour certains projets |
| `api` | Les scripts et la documentation Swagger ([jetons API](#jetons-api)) | Écran **Jetons**, ou jeton personnel |
| `admin` | Les scripts d'administration : toute l'API REST | Ligne de commande uniquement |
| `metrics` | [Prometheus](../reference/metrics.md) | Ligne de commande uniquement |

Aucun jeton ne passe un finding en **Risque accepté** ou **Faux positif** : seule une personne
connectée à l'interface le fait ([triage](triage.md)). Les agents ne font que proposer un statut.

## Créer un jeton dans l'interface

Dans l'écran **Jetons**, un administrateur choisit :

- l'**Usage** : **MCP**, **Pipeline CI/CD** ou **API REST** (avec le **Rôle** qu'il porte) ;
- les **Projets autorisés** : **Tous les projets** (y compris ceux revus plus tard, jamais pour
  un jeton CI/CD) ou **Projets sélectionnés** ;
- la **Validité** : de 30 jours à 1 an.

Un jeton ne donne jamais plus que ce que détient son créateur, et l'écran ne liste que les jetons
des projets que vous lisez. **Projets** change les projets d'un jeton sans changer son secret ;
**Renouveler** remplace son secret.

## Jetons API

Un jeton `api` appelle l'API REST, depuis un script ou depuis la documentation Swagger (bouton
**Authorize**). Il n'atteint jamais le serveur MCP et n'ouvre jamais l'interface. Il en existe
deux sortes :

- **Jeton personnel** : créé par un utilisateur pour lui-même (voir
  [jetons personnels](#jetons-personnels)). Il porte les droits actuels du compte : il n'atteint
  plus rien dès que le compte les perd.
- **Jeton de rôle** : créé par un administrateur dans l'écran **Jetons**, avec un **Rôle**. Il
  porte les permissions de ce rôle sur ses projets. Un rôle utilisé par un jeton ne peut pas être
  supprimé.

## Jetons personnels

Un utilisateur crée ses propres jetons dans **Mon compte** > **Jetons personnels** :

| Usage | Pour |
|---|---|
| **API REST — Swagger et scripts** | L'API REST, avec les droits du compte |
| **MCP / CI — agent et security-review-ci** | Votre agent MCP et `security-review-ci`, sur les projets que votre compte peut lire |

Un jeton personnel suit le compte : ses droits sont ceux du compte, lus à chaque requête ; il
s'arrête tant que le compte doit changer un mot de passe défini par un administrateur, et il est
supprimé avec le compte. Un seul jeton par usage est permis par défaut : révoquez-le pour en
créer un autre. Il ne se renouvelle pas : révoquez-le et créez-en un nouveau.

### Jetons MCP et CI personnels

Le jeton personnel **MCP / CI** connecte votre agent MCP. Il n'est proposé que si vos groupes le
permettent (rôle `mcp-user`, voir [Rôles](access-control.md#roles)). Il atteint les
projets que votre compte peut lire, affichés dans la colonne **Projets**.

Pour un projet qu'il n'atteint pas encore : un administrateur vous en donne l'accès, vous le
créez depuis **Projets** s'il est nouveau et que vous le pouvez, ou votre agent le demande
lui-même avant une revue ; la demande attend alors une validation
([enrôlement](../advanced/mcp-server.md#enrolement-jeton-personnel-et-demande-de-projet)).
Quand le jeton est refusé (révoqué ou expiré), l'agent vous invite à vous reconnecter pour en
créer un nouveau.

Le même jeton sert à [`security-review-ci`](../advanced/ci.md) sur votre poste, par exemple dans
les [hooks de commit](../getting-started/commit-hooks.md) : un seul jeton pour les deux. Un
rapport qu'il enregistre vous désigne comme auteur.

## Points d'attention

- **Le secret n'est affiché qu'une fois**, à la création : copiez-le tout de suite. Seule son
  empreinte est conservée.
- **Après une fuite**, révoquez le jeton, ou renouvelez-le sans délai de grâce : le secret
  divulgué cesse aussitôt de fonctionner.
- **Un jeton expire** : passé sa validité, il n'atteint plus rien. Prévoyez son renouvellement.
- **Une révocation ou un changement de projets s'applique dès la requête suivante.**
- **Un jeton n'ouvre jamais l'interface web**, même un jeton `admin`.
