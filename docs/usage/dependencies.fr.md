# Analyse des dépendances

## Fichiers pris en charge

`requirements*.txt`, `pyproject.toml` (PEP 621/735, Poetry), `poetry.lock`, `Pipfile.lock`,
`uv.lock`, `package.json`, `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` (v1 et
berry), `pom.xml`, `build.gradle(.kts)`.

Dans un `uv.lock`, le projet lui-même et les membres de son workspace (sources `editable` ou
`virtual`) ne sont pas des dépendances et sont ignorés ; toute autre source `git`, `url`,
`path`, `directory` ou `editable` lève `DEP-003`.

## Base de vulnérabilités hors ligne (format OSV)

Le serveur MCP n'appelle aucun service externe : il consulte une base d'avis OSV stockée en
base de données. Deux façons de l'alimenter :

- **import manuel** (aucun accès réseau requis) ;
- **mise à jour quotidienne par le contrôleur**, s'il a le droit de sortir sur Internet,
  directement ou par un proxy.

### Import manuel

Sur une machine connectée, téléchargez les exports d'osv.dev
(`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`, idem `npm` et `Maven`),
transférez-les, puis importez-les (opération réservée à la CLI, idempotente) :

```bash
security-review-controller advisories import PyPI.zip      # .json, dossier ou .zip
security-review-controller advisories import npm.zip
security-review-controller advisories import Maven.zip --ecosystem Maven   # filtre facultatif
security-review-controller advisories status
```

### Mise à jour automatique par le contrôleur

Avec `SECREVIEW_OSV_AUTO_UPDATE=true`, `security-review-controller serve` télécharge les
exports `all.zip` de chaque écosystème et les importe, puis recommence toutes les 24 heures :

```bash
SECREVIEW_OSV_AUTO_UPDATE=true
# Facultatif : proxy HTTP sortant du contrôleur (identifiants acceptés, jamais journalisés)
SECREVIEW_PROXY=http://utilisateur:motdepasse@proxy.example.com:3128
```

- **Désactivée par défaut**. Le serveur MCP, lui, ne se connecte jamais à l'extérieur.
- L'échéance dépend de l'âge de la base (dernier import, manuel ou automatique) : un
  redémarrage ou une seconde réplique du contrôleur ne retélécharge pas avant la fin de
  l'intervalle (`SECREVIEW_OSV_UPDATE_INTERVAL_HOURS`, 24 par défaut). Une base vide ou trop
  ancienne est mise à jour dès le démarrage.
- **Proxy** : le téléchargement passe par le proxy sortant du contrôleur, `SECREVIEW_PROXY`
  (`http://[utilisateur:mot de passe@]hôte:port`, tunnel `CONNECT` vers le site HTTPS), sauf
  vers les hôtes de `SECREVIEW_NO_PROXY`. Le même proxy sert à la
  [connexion SSO](web-interface.md#connexion-sso-openid-connect). Sans lui, les variables
  standard `HTTPS_PROXY` et `NO_PROXY` s'appliquent. Si le proxy inspecte le TLS, donnez sa CA
  avec `SECREVIEW_OSV_CAFILE` (elle remplace alors les CA du système).
- **Miroir** : `SECREVIEW_OSV_URL` remplace la source (Nexus, Artifactory, bucket interne…)
  tant qu'il sert `<URL>/<écosystème>/all.zip` en HTTPS. HTTP en clair, identifiants dans l'URL
  et redirections vers autre chose que HTTPS sont refusés.
- `SECREVIEW_OSV_ECOSYSTEMS` (`PyPI,npm,Maven` par défaut) limite les exports téléchargés ;
  chaque archive est bornée par `SECREVIEW_OSV_MAX_DOWNLOAD_MB` (1024 Mio), écrite dans un
  dossier temporaire puis supprimée.
- Un écosystème en échec (réseau, taille, archive invalide) n'empêche pas les autres ; il est
  journalisé et une nouvelle tentative a lieu une heure plus tard.

#### Hôtes sans proxy

`SECREVIEW_NO_PROXY` (ou la liste de l'écran **Paramètres**) donne, séparées par des virgules,
les destinations jointes **sans** le proxy :

| Entrée | Exemple | Effet |
|---|---|---|
| Domaine | `corp.example` ou `.corp.example` | Le domaine et tous ses sous-domaines (`sso.corp.example`) |
| Joker de sous-domaines | `*.corp.example` | Identique à `.corp.example` |
| Adresse IP | `10.0.0.5`, `[fd00::5]` | Cette adresse (un port éventuel, `10.0.0.5:8443`, est ignoré) |
| Plage CIDR | `10.0.0.0/8`, `192.168.1.128/25`, `fd00::/8` | Toute adresse IPv4 ou IPv6 de la plage |
| Tout | `*` | Aucune connexion ne passe par le proxy |

Comme curl, une adresse ou une plage CIDR ne s'applique qu'à une URL dont l'hôte **est** une
adresse IP (`https://10.1.2.3/...`) : un nom d'hôte n'est jamais résolu pour être comparé à une
plage. Pour contourner le proxy vers un serveur interne joint par son nom, indiquez son domaine.
La boucle locale (`localhost`, `127.0.0.0/8`, `::1`) est toujours jointe directement. Une plage
invalide (`10.0.0.0/33`, `example.com/chemin`) est refusée.

```bash
SECREVIEW_NO_PROXY=.corp.example,10.0.0.0/8,172.16.0.0/12,fd00::/8
```

Le proxy peut aussi être choisi par un administrateur dans l'écran
[**Paramètres**](web-interface.md#ecrans) de l'interface web : proxy et hôtes sans proxy
définis ici, ou connexion directe, prioritaires sur `SECREVIEW_PROXY`, `SECREVIEW_NO_PROXY` et
`HTTPS_PROXY` ; ils s'appliquent au téléchargement suivant. Le même écran affiche l'état de
la base, l'historique des mises à jour (planifiées, CLI ou web) et un bouton **Mettre à jour
maintenant** (lancement en arrière-plan, une mise à jour à la fois), disponible seulement quand
`SECREVIEW_OSV_AUTO_UPDATE=true`.

Pour déclencher une mise à jour à la demande (ou depuis un `CronJob` plutôt que depuis le
contrôleur), avec les mêmes paramètres :

```bash
security-review-controller advisories update                  # écosystèmes de SECREVIEW_OSV_ECOSYSTEMS
security-review-controller advisories update --ecosystem npm  # option répétable
# code de sortie : 0 = tout importé, 2 = au moins un écosystème en échec ou paramètre invalide
```

Le contrôleur télécharge au plus quelques centaines de Mio par jour (l'export npm est le plus
gros) : prévoyez l'espace correspondant dans son dossier temporaire (`/tmp`).

## Scan en pipeline

Pour les gros lockfiles, préférez la CLI à l'outil MCP, limité à
`SECREVIEW_MAX_DEPENDENCY_CHARS` :

```bash
security-review-controller deps scan package-lock.json requirements.txt \
    --fail-on high --require-database --project mon-projet --save
# code de sortie : 0 = ok, 1 = bloqué, 2 = erreur
```

## Lire le résultat

Le champ `vulnerability_check` dit si la vérification a eu lieu :

| Valeur | Signification |
|---|---|
| `performed` | Les versions ont été comparées à la base |
| `skipped_no_advisory_database` | Aucune base importée |
| `skipped_no_advisories_for_ecosystem` | Aucun avis pour cet écosystème |

!!! danger "Liste vide ≠ dépendances sûres"
    Dans les deux derniers cas, **une liste vide ne signifie pas que les dépendances sont
    sûres**. `--require-database` fait échouer le pipeline dans ce cas.

- Une base de plus de 30 jours est signalée.
- Une sévérité absente de l'avis est traitée comme `medium` (`severity_known: false`).
- Les versions en intervalle (`>=2`) ne sont pas vérifiables : analysez le lockfile.
- Règles d'hygiène `DEP-001` à `DEP-009` : versions non épinglées, URL / VCS, HTTP, index
  supplémentaire, `--trusted-host`, etc.
