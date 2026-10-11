# Interface web

L'interface web permet aux équipes sécurité de consulter les rapports enregistrés par les agents
et de **trier les findings** (corrigé, risque accepté, faux positif) sans passer par un client
MCP. Elle est servie par le transport `streamable-http`, sur le même port que l'endpoint MCP :

| Chemin | Contenu |
|---|---|
| `/mcp` | Endpoint MCP (agents, CI/CD) |
| `/ui/` | Application web (Angular) |
| `/api/v1/…` | API REST utilisée par l'application |
| `/api/docs` | Documentation OpenAPI de l'API REST |

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
- **Règles** : les administrateurs créent, modifient, suppriment, activent ou désactivent les
  règles personnalisées des packs TOML et peuvent recharger les fichiers modifiés hors de l'UI.
  L'écran nécessite `SECREVIEW_RULES_DIR` et ne modifie pas les règles intégrées.

## Rôles

Chaque jeton porte un rôle, qui détermine les endpoints accessibles :

| Rôle | `/mcp` | Interface web (lecture) | Changement de statut |
|---|---|---|---|
| `mcp` (défaut) | ✅ | — | — |
| `reader` | — | ✅ | — |
| `triager` | — | ✅ | ✅ |
| `web-admin` | — | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ |

Dans l'image Docker, un mot de passe `web-admin` est généré au premier démarrage HTTP et affiché
une seule fois dans les logs. Son empreinte est persistée dans `/data/admin-token` : conservez le
volume `/data` pour garder ce compte et son mot de passe après redémarrage. Ce rôle peut gérer les
règles TOML et trier les findings, mais n'accède pas à `/mcp`. Le rôle `admin` existant conserve
l'accès à l'interface web et à MCP. Un jeton créé sans rôle reste `mcp` : les jetons des agents
et de la CI gardent leur accès mais ne peuvent pas utiliser l'interface web. Le rôle `triager`
conserve uniquement le triage des findings. Générez un jeton par personne :

Le mot de passe affiché dans les logs doit être traité comme un secret: restreignez l'accès aux
journaux. S'il est perdu, arrêtez le serveur, supprimez le fichier bootstrap et redémarrez pour
en générer un nouveau.

```bash
security-review-mcp token --label alice --role triager
# {"token": "UJB7…", "config_entry": "alice:triager:sha256:1f91…"}
```

Ajoutez `config_entry` au fichier `SECREVIEW_AUTH_TOKENS_FILE` et transmettez `token` à la
personne, qui le colle sur la page de connexion. Chaque changement de statut est journalisé avec
le label du jeton :

```
INFO security_review_mcp.web: Finding 42 set to accepted by alice
```

!!! warning "Sans jeton configuré, tout le monde est administrateur"
    Hors image Docker, si aucun jeton ni fichier de bootstrap n'est configuré, l'interface est
    accessible sans connexion, avec tous les droits. Ne le faites qu'en local
    (`--host 127.0.0.1`), où les requêtes dont l'en-tête `Host` n'est pas `localhost` sont
    rejetées (protection contre le DNS rebinding).

## Sécurité

- Les fichiers statiques de `/ui/` sont publics (ils ne contiennent aucune donnée) ; l'API
  exige un jeton `reader`, `triager` ou `admin`.
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
| `SECREVIEW_AUTH_BOOTSTRAP_FILE` | — | Fichier du mot de passe admin initial; défini à `/data/admin-token` dans Docker |

Le paquet publié et l'image Docker contiennent l'application déjà compilée. Si vous installez
depuis les sources sans la compiler, seule l'API REST est servie et un avertissement est
journalisé. Voir [Contribuer](../contribuer.md#interface-web) pour la compiler.
