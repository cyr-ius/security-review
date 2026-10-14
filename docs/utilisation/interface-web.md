# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le **contrôleur**, un processus distinct du serveur MCP qui partage sa
base de données (voir [Architecture et déploiement](../demarrage/kubernetes.md)) :

| Chemin | Contenu |
|---|---|
| `/ui/` | Application web (Angular) |
| `/api/v1/…` | API REST utilisée par l'application |
| `/api/docs` | Documentation OpenAPI de l'API REST (publique, sans données) |
| `/healthz` | Sonde de vie (publique) |

```bash
security-review-controller serve --host 127.0.0.1 --port 8080
# interface : http://127.0.0.1:8080/ui/
```

## Écrans

Les écrans sont accessibles depuis la barre latérale : **Supervision** (projets, rapports) pour
tous les rôles, **Administration** (règles, checklists, jetons) pour le rôle `admin`. Le bas de
la barre affiche le client connecté, son rôle et la version, avec le bouton de déconnexion ; sur
petit écran, la barre s'ouvre avec le bouton de menu. Le thème clair ou sombre se choisit en haut
à droite, y compris sur la page de connexion, et reste mémorisé dans le navigateur.

- **Projets** : tous les projets avec leurs findings ouverts par sévérité, triés par risque,
  activité ou nom.
- **Projet** : findings ouverts, tendance sur 30 jours à 1 an (graphique et tableau), délai
  moyen de correction, plus ancien finding ouvert, CWE les plus fréquentes, derniers rapports et
  export SARIF.
- **Rapports** : liste filtrable par projet et niveau de risque (les filtres sont dans l'URL, on
  peut donc partager un lien).
- **Rapport** : résumé, contexte (dépôt, branche, commit), findings avec emplacement, CWE,
  extrait de code et recommandation ; téléchargement Markdown et SARIF. Les utilisateurs qui ont
  le rôle `triager` ou `admin` changent le statut d'un finding directement depuis cet écran.
- **Checklists** : les administrateurs consultent les items de contrôle par domaine, filtrent la
  liste et créent, modifient ou suppriment les items personnalisés. Les items par défaut peuvent
  être modifiés, mais pas supprimés. Toute modification est rechargée immédiatement par le serveur
  et intégrée aux prompts de revue.
- **Règles** : les administrateurs consultent toutes les [règles](regles.md) stockées en base,
  filtrables par origine (par défaut ou personnalisée). Ils créent, modifient (dans une fenêtre
  modale, sans quitter la position dans la liste), activent ou désactivent les règles, et
  suppriment les règles personnalisées. Une règle par défaut peut être
  modifiée (badge « Par défaut, modifiée ») ou désactivée, mais pas supprimée. Le bouton
  **Recharger** applique immédiatement un changement fait avec la CLI
  `security-review-controller rules`.
- **Jetons** : les administrateurs créent et révoquent des jetons de rôle `reader`, `triager` ou
  `mcp`, limités à un ou plusieurs projets. Le rôle `admin` reste non restreint et se crée par la
  CLI. Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante. La section
  **Demandes en attente** distingue les nouveaux jetons des demandes d'accès à un projet
  supplémentaire ([enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton)) :
  **Approuver** active le nouveau jeton ou ajoute le projet au jeton existant ; **Refuser** ne
  supprime que la demande. Les projets autorisés et les ajouts encore en attente sont affichés
  pour chaque jeton.

## Rôles

Chaque jeton porte un rôle, qui détermine les endpoints accessibles :

| Rôle | `/mcp` | Interface web (lecture) | Changement de statut |
|---|---|---|---|
| `mcp` (défaut) | ✅ | — | — |
| `reader` | — | ✅ | — |
| `triager` | — | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ |

Un jeton `mcp`, `reader` ou `triager` restreint avec `--project` ne voit et ne trie que les
projets autorisés ; l'option peut être répétée (voir
[jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)).

Dans l'image Docker, un mot de passe `admin` est généré au premier démarrage du contrôleur et
affiché une seule fois dans ses logs. Son empreinte est enregistrée dans la base de données, comme celle
de tous les jetons (voir [jetons Bearer](../demarrage/http.md#jetons-bearer)). Ce rôle peut gérer les
règles internes, trier les findings et accéder à `/mcp`. Un jeton créé sans rôle reste `mcp` : les jetons des agents
et de la CI gardent leur accès mais ne peuvent pas utiliser l'interface web. Le rôle `triager`
conserve uniquement le triage des findings. Générez un jeton par personne :

Le mot de passe affiché dans les logs doit être traité comme un secret: restreignez l'accès aux
journaux. S'il est perdu, générez-en un nouveau (l'ancien est aussitôt invalidé) :
`security-review-controller token reset-admin`.

```bash
security-review-controller token create --label alice --role triager
# {"id": "…", "label": "alice", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
```

Transmettez `token` à la personne, qui le colle sur la page de connexion. Révoquez-le avec
`security-review-controller token revoke alice`. Chaque changement de statut est journalisé avec
le label du jeton :

```
INFO security_review_mcp.web: Finding 42 set to accepted by alice
```

!!! warning "Authentification requise pour la Web UI"
  L'API de l'interface refuse les requêtes avec le statut `503` si aucun jeton n'est configuré;
  la mire de connexion reste affichée et indique que l'authentification doit être configurée.
  Créez un jeton avec `security-review-controller token create` ou activez
  `SECREVIEW_AUTH_BOOTSTRAP_ADMIN`. Cette restriction
  concerne la Web UI; l'authentification MCP reste indépendante.

## Sécurité

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige un jeton `reader`, `triager` ou `admin`. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont publics et ne donnent accès à aucune donnée.
  Dans Swagger, le cadenas d'une route indique qu'elle exige un jeton : il reste **ouvert**
  tant que vous n'avez pas saisi de jeton avec **Authorize**, et ne veut pas dire que la route
  est accessible sans jeton.
- Le contrôleur n'expose aucune route d'écriture sans jeton. Les demandes
  d'[enrôlement](../demarrage/http.md#enrolement-un-projet-demande-son-jeton) sont déposées sur
  le **serveur MCP** (`POST /api/v1/enroll`, public) ; le contrôleur les liste et les traite
  (`GET /api/v1/enrollments`, `POST /api/v1/enrollments/{id}/approve`,
  `DELETE /api/v1/enrollments/{id}`, rôle `admin`). Il peut donc rester sur un réseau interne.
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
- Il est conservé dans le `sessionStorage` de l'onglet et disparaît à sa fermeture.
- Les pages sont servies avec une CSP stricte (`script-src 'self'`, aucune ressource externe),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`.
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](../demarrage/http.md#tls)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Sert l'interface sur `/ui` ; à `false`, le contrôleur ne sert que l'API REST |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'application (défaut : celle du paquet) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Génère le mot de passe admin initial (stocké en base) au démarrage du contrôleur ; `true` dans Docker |
| `SECREVIEW_ENROLLMENT` | `true` | Demandes de jetons par les projets (sur le serveur MCP), validées dans l'écran **Jetons** |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, le contrôleur ne sert que l'API REST et un avertissement est
journalisé. Voir [Contribuer](../contribuer.md#interface-web) pour la compiler.
