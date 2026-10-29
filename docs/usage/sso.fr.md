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
- un claim qui contient les **groupes** de l'utilisateur (souvent `groups`).

Le fournisseur doit être joignable en HTTPS par le serveur Controller, par le proxy sortant au besoin.

## Configurer le OIDC dans l'interface

Un administrateur remplit l'écran **Connexions**, sans redémarrer le serveur Controller :

1. **Émetteur (issuer)**, **Identifiant client**, **Secret client** (vide pour un client public)
   et **URL de retour** ;
2. le **Claim des groupes**, et les **Groupes administration** dont les membres deviennent
   administrateurs ;
3. **Créer les utilisateurs à leur première connexion**, ou laissez-la désactivée et créez chaque
   compte OIDC dans **Utilisateurs** ;
4. **Tester la connexion**, puis **Activer la connexion OIDC** et enregistrer.

Un changement s'applique à la connexion suivante. Un champ qui porte le badge **Variable**
(cadenas) est défini par le déploiement et ne se modifie pas ici. Le secret client n'est jamais
réaffiché : laissé vide, il est conservé.

## Comptes OIDC

Chaque utilisateur OIDC est un compte de l'écran **Utilisateurs**, avec le badge **OIDC** et sans
mot de passe. Il est lié à sa première connexion à son identité chez le fournisseur : un nom
changé chez le fournisseur garde le même compte.

| Situation à la connexion | Résultat |
|---|---|
| Compte connu | Connexion |
| Aucun compte, création automatique activée | Le compte est créé, si ses groupes lui donnent une permission |
| Aucun compte, création automatique désactivée | Refus : un administrateur crée d'abord le compte OIDC |
| Un compte **local** porte le même nom | Refus : une connexion OIDC n'ouvre jamais un compte local |
| Compte supprimé par un administrateur | Refus jusqu'à **Autoriser à nouveau** dans **Utilisateurs** |

## Groupes du fournisseur d'identité

À chaque connexion, l'utilisateur rejoint chaque groupe **Ouvert au OIDC** dont le nom est
**exactement** l'un des groupes envoyés par le fournisseur (casse comprise), et quitte ceux qu'il
n'a plus. Les autres valeurs sont ignorées : créez un groupe du même nom pour en utiliser une.

Exemple : le fournisseur envoie `["payments-team", "staff"]` ; un groupe `payments-team` ouvert
au OIDC donne le rôle `triager` sur `billing`, et aucun groupe ne s'appelle `staff`. L'utilisateur
ne trie alors que `billing`.

Un groupe non ouvert au OIDC (par exemple `administrators`) n'est jamais rejoint de cette façon.

## Lecture du projet

Pour qu'un développeur lise un projet, ajoutez son compte OIDC au
[groupe de projet](projects.md#groupe-de-projet) dans **Groupes** ou **Utilisateurs**, ou validez
la demande d'accès de son agent dans **Projets**. Le compte doit d'abord exister : le développeur
s'est connecté une fois (création automatique), ou un administrateur l'a créé dans
**Utilisateurs**.

## OIDC seul

Le déploiement peut faire du fournisseur d'identité la **seule** porte d'entrée : la page de
connexion ne propose alors que son bouton. Cela ne s'applique que tant que le OIDC fonctionne,
pour que personne ne reste bloqué si le fournisseur est mal configuré
([OIDC seul](../advanced/oidc.md#oidc-seul)).

## Sessions

- Une session dure 8 heures par défaut. Un changement de groupes chez le fournisseur s'applique à
  la connexion suivante ; un changement fait dans l'interface, aussitôt.
- **Se déconnecter** ferme la session de l'interface, pas celle du fournisseur d'identité.
- En cas d'échec, la page de connexion indique la cause (accès refusé, compte pas encore créé ou
  supprimé, nom pris par un compte local...).

## Points d'attention

- **Gardez un administrateur local** : si le fournisseur devient injoignable, il reste le seul
  accès, en plus de la ligne de commande.
- **Les noms de groupes doivent correspondre exactement**, casse comprise, et le groupe doit être
  **Ouvert au OIDC**.
- **Supprimer un compte OIDC** l'empêche d'être recréé à sa prochaine connexion, même avec la
  création automatique ; **Autoriser à nouveau** lève cette interdiction.
- **Un utilisateur dont les groupes ne donnent aucune permission** ne peut pas se connecter.
