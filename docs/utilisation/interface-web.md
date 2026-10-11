# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le transport `streamable-http`, sur le même port que l'endpoint MCP :

| Chemin | Contenu |
|---|---|
| `/mcp` | Endpoint MCP (agents, CI/CD) |
| `/ui/` | Application web (Angular) |
| `/api/v1/…` | API REST utilisée par l'application |
| `/api/docs` | Documentation OpenAPI de l'API REST (publique, sans données) |

```bash
security-review-mcp --transport streamable-http --host 127.0.0.1 --port 8000
# interface : http://127.0.0.1:8000/ui/
```

## Écrans

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
- **Règles** : les administrateurs consultent toutes les [règles](regles.md) stockées en base,
  filtrables par origine (par défaut ou personnalisée). Ils créent, modifient, activent ou
  désactivent les règles, et suppriment les règles personnalisées. Une règle par défaut peut être
  modifiée (badge « Par défaut, modifiée ») ou désactivée, mais pas supprimée. Le bouton
  **Recharger** applique immédiatement un changement fait avec la CLI
  `security-review-mcp rules`.
- **Jetons** : les administrateurs créent et révoquent des jetons en lecture limités à un projet.
  Le secret n'est montré qu'une fois ; seule son empreinte est enregistrée, dans la base de
  données. Une révocation prend effet à la requête suivante.

## Rôles

Chaque jeton porte un rôle, qui détermine les endpoints accessibles :

| Rôle | `/mcp` | Interface web (lecture) | Changement de statut |
|---|---|---|---|
| `mcp` (défaut) | ✅ | — | — |
| `reader` | — | ✅ | — |
| `triager` | — | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ |

Un jeton `mcp`, `reader` ou `triager` créé avec `--project` ne voit et ne trie que ce projet
(voir [jetons restreints à un projet](../demarrage/http.md#jetons-restreints-a-un-projet)).

Dans l'image Docker, un mot de passe `admin` est généré au premier démarrage HTTP et affiché
une seule fois dans les logs. Son empreinte est enregistrée dans la base de données, comme celle
de tous les jetons (voir [jetons Bearer](../demarrage/http.md#jetons-bearer)). Ce rôle peut gérer les
règles internes, trier les findings et accéder à `/mcp`. Un jeton créé sans rôle reste `mcp` : les jetons des agents
et de la CI gardent leur accès mais ne peuvent pas utiliser l'interface web. Le rôle `triager`
conserve uniquement le triage des findings. Générez un jeton par personne :

Le mot de passe affiché dans les logs doit être traité comme un secret: restreignez l'accès aux
journaux. S'il est perdu, générez-en un nouveau (l'ancien est aussitôt invalidé) :
`security-review-mcp token reset-admin`.

```bash
security-review-mcp token create --label alice --role triager
# {"id": "…", "label": "alice", "role": "triager", "project": null, "created_at": "…", "token": "UJB7…"}
```

Transmettez `token` à la personne, qui le colle sur la page de connexion. Révoquez-le avec
`security-review-mcp token revoke alice`. Chaque changement de statut est journalisé avec
le label du jeton :

```
INFO security_review_mcp.web: Finding 42 set to accepted by alice
```

!!! warning "Authentification requise pour la Web UI"
  L'API de l'interface refuse les requêtes avec le statut `503` si aucun jeton n'est configuré;
  la mire de connexion reste affichée et indique que l'authentification doit être configurée.
  Créez un jeton avec `security-review-mcp token create` ou activez
  `SECREVIEW_AUTH_BOOTSTRAP_ADMIN`. Cette restriction
  concerne la Web UI; l'authentification MCP reste indépendante.

## Sécurité

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  `/api/v1/` exige un jeton `reader`, `triager` ou `admin`. La documentation Swagger (`/api/docs`)
  et son schéma (`/api/openapi.json`) sont publics et ne donnent accès à aucune donnée.
- Le jeton est envoyé dans l'en-tête `Authorization` : pas de cookie, donc pas de CSRF.
- Il est conservé dans le `sessionStorage` de l'onglet et disparaît à sa fermeture.
- Les pages sont servies avec une CSP stricte (`script-src 'self'`, aucune ressource externe),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`.
- Servez l'interface en HTTPS ([TLS intégré ou reverse proxy](../demarrage/http.md#tls)) dès
  qu'elle n'écoute plus sur localhost : le jeton circule à chaque requête.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `SECREVIEW_WEB_UI` | `true` | Active l'API REST et l'interface sur le transport HTTP |
| `SECREVIEW_WEB_UI_DIR` | — | Dossier d'une autre build de l'application (défaut : celle du paquet) |
| `SECREVIEW_AUTH_BOOTSTRAP_ADMIN` | `false` | Génère le mot de passe admin initial (stocké en base) ; `true` dans Docker |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, seule l'API REST est servie et un avertissement est
journalisé. Voir [Contribuer](../contribuer.md#interface-web) pour la compiler.
