# Connexion OIDC (OpenID Connect)

Cette page est facultative : les [comptes locaux](user-accounts.md) suffisent pour démarrer. La
connexion OIDC permet aux personnes de se connecter à l'interface web avec le fournisseur
d'identité de votre entreprise (Keycloak, Microsoft Entra ID, Okta, Authentik, Dex...). La page de
connexion affiche alors un bouton pour le fournisseur au-dessus du formulaire des comptes locaux,
qui reste disponible.

Les variables, l'API, le flux et les règles détaillées sont dans
[Connexion OIDC en détail](../advanced/oidc.md).

## Déclarer le client chez le fournisseur

Chez votre fournisseur d'identité, créez un client OIDC (avec ou sans secret) et donnez-lui :

- l'**URL de retour** `https://<contrôleur>/api/v1/auth/oidc/callback`, exactement telle que le
  navigateur la voit (derrière un reverse proxy, l'adresse du proxy) ;
- un claim qui contient les **groupes** ou rôles de l'utilisateur (souvent `groups`).

Le fournisseur doit être joignable en HTTPS par le serveur Controller, par le proxy sortant au besoin.

## Configurer le OIDC dans l'interface

Un administrateur remplit la page **Connexions**, sans redémarrer le serveur Controller :

1. **Émetteur (issuer)**, **Identifiant client**, **Secret client** (vide pour un client public)
   et **URL de retour** ;
2. le **Claim des rôles**, et les **Groupes administration** dont les membres deviennent
   administrateurs ;
3. **Créer les utilisateurs à leur première connexion**, ou laissez-la désactivée et créez chaque
   compte OIDC dans **Utilisateurs** ;
4. **Tester la connexion**, puis **Activer la connexion OIDC** et enregistrer.

Un changement s'applique à la connexion suivante. Un champ qui porte le badge **Variable**
(cadenas) est défini par le déploiement et ne se modifie pas ici. Le secret client n'est jamais
réaffiché : laissé vide, il est conservé.

## Comptes OIDC

Chaque utilisateur OIDC est un compte de la page **Utilisateurs**, avec le badge **OIDC** et sans
mot de passe. Il est lié à sa première connexion à son identité chez le fournisseur : un nom
changé chez le fournisseur garde le même compte.

| Situation à la connexion | Résultat |
|---|---|
| Compte connu | Connexion |
| Aucun compte, création automatique activée | Le compte est créé, si ses correspondances lui donnent une permission |
| Aucun compte, création automatique désactivée | Refus : un administrateur crée d'abord le compte OIDC |
| Un compte **local** porte le même nom | Refus : une connexion OIDC n'ouvre jamais un compte local |
| Compte supprimé par un administrateur | Refus jusqu'à **Autoriser à nouveau** dans **Utilisateurs** |

## Correspondances OIDC

En bas de la page **Connexions**, chaque **correspondance OIDC** d'une valeur donne des **rôles**,
des droits par projet sur **Tous les projets** et des **projets** avec leurs droits aux
utilisateurs OIDC dont le fournisseur d'identité envoie **exactement** cette valeur (casse
comprise). Ils s'ajoutent aux rôles et projets donnés au compte dans **Utilisateurs**. À chaque
connexion, les valeurs du claim nommées par une correspondance sont conservées ; les autres
valeurs sont ignorées. Un changement des correspondances s'applique aussitôt aux utilisateurs
OIDC, par les valeurs de leur dernière connexion.

Exemple : le fournisseur envoie `["payments-team", "staff"]` ; une correspondance donne à
`payments-team` le projet `billing` avec **Lire les rapports** et **Trier les findings**, et aucune
correspondance ne nomme `staff`. L'utilisateur lit et trie alors `billing`, et garde les projets
donnés au compte.

Un projet pas encore créé est ignoré jusqu'à sa création, jamais créé par le fournisseur
d'identité. Chaque valeur des **Groupes administration** reçoit une correspondance vers `admin`,
avec la lecture, l'écriture et le triage de tous les projets, à chaque connexion d'un utilisateur qui la
porte tant qu'aucune correspondance ne la nomme : une correspondance modifiée ensuite est
conservée, une correspondance supprimée revient. Pour retirer durablement `admin` à un groupe,
retirez sa valeur de `SECREVIEW_OIDC_ADMIN_GROUPS`, ou associez-la à un autre rôle.

## Lecture du projet

Pour qu'un développeur lise un projet, donnez ce projet à son compte OIDC dans **Utilisateurs** ou
dans les [membres](projects.md#membres) du projet (lecture par défaut ; ajoutez **Écrire les
rapports** pour que son agent y enregistre ses revues), faites correspondre l'un de ses groupes,
ou validez la demande d'accès de son agent dans **Projets** (lecture et écriture).
Donner un projet à un compte exige qu'il existe : le développeur s'est connecté une fois
(création automatique), ou un administrateur l'a créé dans **Utilisateurs**.

## OIDC seul

Le déploiement peut faire du fournisseur d'identité la **seule** porte d'entrée : la page de
connexion ne propose alors que son bouton. Cela ne s'applique que tant que le OIDC fonctionne,
pour que personne ne reste bloqué si le fournisseur est mal configuré
([OIDC seul](../advanced/oidc.md#oidc-seul)).

## Sessions

- Une session dure 8 heures par défaut. Un changement de groupes chez le fournisseur s'applique à
  la connexion suivante ; un changement fait dans l'interface (rôles, correspondances), aussitôt.
- **Se déconnecter** ferme la session de l'interface, pas celle du fournisseur d'identité.
- En cas d'échec, la page de connexion indique la cause (accès refusé, compte pas encore créé ou
  supprimé, nom pris par un compte local...).

## Points d'attention

- **Gardez un administrateur local** : si le fournisseur devient injoignable, il reste le seul
  accès, en plus de la ligne de commande.
- **Les valeurs d'une correspondance doivent correspondre exactement** aux groupes envoyés par le
  fournisseur, casse comprise.
- **Supprimer un compte OIDC** l'empêche d'être recréé à sa prochaine connexion, même avec la
  création automatique ; **Autoriser à nouveau** lève cette interdiction.
- **Un utilisateur dont les rôles, projets et correspondances ne donnent aucune permission** ne
  peut pas se connecter : un projet pas encore créé ne donne rien.
