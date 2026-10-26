# Analyse des dépendances

## Fichiers pris en charge

`requirements*.txt`, `pyproject.toml` (PEP 621/735, Poetry), `poetry.lock`, `Pipfile.lock`,
`uv.lock`, `package.json`, `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` (v1 et
berry), `pom.xml`, `build.gradle(.kts)`, `go.mod`, `Cargo.lock`, `Cargo.toml`,
`packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj`, `Directory.Packages.props`,
`Directory.Build.props`, `packages.config`, `nuget.config`, SBOM CycloneDX (`bom.json`,
`bom.xml`, `sbom.json`, `*.cdx.json`, `*.cdx.xml`...).

| Écosystème | Fichier à analyser en priorité | Remarques |
|---|---|---|
| Go | `go.mod` | Depuis Go 1.17, il liste tous les modules de la compilation (`// indirect` compris) à leur version sélectionnée : il est traité comme un lockfile. Les directives `replace` sont appliquées (un fork lève `DEP-003`, un chemin local `DEP-007`). Les pseudo-versions (`v0.0.0-<date>-<commit>`) sont comparées par date. La bibliothèque standard (directives `go` et `toolchain`) n'est pas vérifiée : analysez le binaire avec `govulncheck`. |
| Rust (crates.io) | `Cargo.lock` | Toutes les crates de la compilation, transitives comprises ; les membres du workspace sont ignorés. Une source `git` lève `DEP-003`, un autre registre `DEP-005`. `Cargo.toml` ne contient que des plages (`"1.0"` vaut `^1.0`) : il est contrôlé pour l'hygiène (`*`, `git`, `path`, `registry`, `[patch]`, `workspace = true`). |
| .NET (NuGet) | `packages.lock.json` | Activez-le avec `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` ; les paquets de chaque framework cible sont vérifiés. Dans un `*.csproj`, `Version="1.2.3"` est la version restaurée (la plus basse applicable) et elle est vérifiée ; les versions flottantes (`1.*`) lèvent `DEP-002`, les versions gérées dans `Directory.Packages.props` ou par une propriété MSBuild `DEP-009`. `nuget.config` est contrôlé pour les sources HTTP (`DEP-004`) et pour plusieurs sources sans `packageSourceMapping` (`DEP-005`, confusion de dépendances). |

Dans un `uv.lock`, le projet lui-même et les membres de son workspace (sources `editable` ou
`virtual`) ne sont pas des dépendances et sont ignorés ; toute autre source `git`, `url`,
`path`, `directory` ou `editable` lève `DEP-003`.

### SBOM CycloneDX (dépendances transitives)

`pom.xml` et `build.gradle` ne listent que les dépendances directes : leurs dépendances
transitives, souvent les vulnérables, ne sont pas vérifiées (une note le rappelle dans le
résultat). Générez dans le pipeline un SBOM CycloneDX de l'arbre de dépendances résolu, puis
analysez-le :

```bash
# Maven : écrit target/bom.json et target/bom.xml
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
security-review-ci scan-deps target/bom.json --project mon-projet --require-database
```

Avec Gradle, la tâche `cyclonedxBom` du plugin `org.cyclonedx.bom` produit le même fichier ;
`npm sbom --sbom-format cyclonedx` le fait pour npm.

- Le SBOM est lu en JSON (`bomFormat: "CycloneDX"`) ou en XML (espace de noms CycloneDX) ; les
  composants imbriqués sont inclus. Un SBOM XML contenant un `DOCTYPE` ou une `ENTITY` est refusé.
- Chaque composant est identifié par son package URL (`purl`) : `pkg:maven/...` (Maven),
  `pkg:npm/...` (npm), `pkg:pypi/...` (PyPI), `pkg:golang/...` (Go), `pkg:cargo/...`
  (crates.io) et `pkg:nuget/...` (NuGet). Un SBOM peut mélanger ces écosystèmes. Les autres
  types (`pkg:gem`, `pkg:composer`...) et les composants sans `purl` sont comptés dans une note
  et ne sont pas vérifiés.
- Les versions sont résolues : le SBOM est traité comme un lockfile. Un composant de portée
  `excluded` est marqué `dev` ; une version Maven `-SNAPSHOT` lève `DEP-002`.

## Base de vulnérabilités hors ligne (format OSV)

Le serveur MCP n'appelle aucun service externe : il consulte une base d'avis OSV stockée en
base de données. Deux façons de l'alimenter :

- **import manuel** (aucun accès réseau requis) ;
- **mise à jour quotidienne par le contrôleur**, s'il a le droit de sortir sur Internet,
  directement ou par un proxy.

### Import manuel

Sur une machine connectée, téléchargez les exports d'osv.dev
(`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`, idem `npm`, `Maven`, `Go`,
`crates.io` et `NuGet`), transférez-les, puis importez-les (opération réservée à la CLI, idempotente) :

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
HTTPS_PROXY=http://utilisateur:motdepasse@proxy.example.com:3128
```

- **Désactivée par défaut**. Le serveur MCP, lui, ne se connecte jamais à l'extérieur.
- L'échéance dépend de l'âge de la base (dernier import, manuel ou automatique) : un
  redémarrage ou une seconde réplique du contrôleur ne retélécharge pas avant la fin de
  l'intervalle (`SECREVIEW_OSV_UPDATE_INTERVAL_HOURS`, 24 par défaut). Une base vide ou trop
  ancienne est mise à jour dès le démarrage.
- **Proxy** : le téléchargement passe par le proxy sortant du contrôleur, donné par les
  variables standard `HTTPS_PROXY` (sinon `HTTP_PROXY` ; noms en minuscules acceptés ;
  `http://[utilisateur:mot de passe@]hôte:port`, `hôte:port` valant `http://hôte:port`, tunnel
  `CONNECT` vers le site HTTPS), sauf vers les hôtes de `NO_PROXY`. Le même proxy sert à la
  [connexion OIDC](../../advanced/oidc.md). Sans ces variables, la connexion est directe. Si le proxy inspecte
  le TLS, donnez sa CA avec `SECREVIEW_OSV_CAFILE` (elle remplace alors les CA du système).
- **Miroir** : `SECREVIEW_OSV_URL` remplace la source (Nexus, Artifactory, bucket interne…)
  tant qu'il sert `<URL>/<écosystème>/all.zip` en HTTPS. HTTP en clair, identifiants dans l'URL
  et redirections vers autre chose que HTTPS sont refusés.
- `SECREVIEW_OSV_ECOSYSTEMS` (`PyPI,npm,Maven,Go,crates.io,NuGet` par défaut) limite les exports téléchargés ;
  chaque archive est bornée par `SECREVIEW_OSV_MAX_DOWNLOAD_MB` (1024 Mio), écrite dans un
  dossier temporaire puis supprimée.
- Un écosystème en échec (réseau, taille, archive invalide) n'empêche pas les autres ; il est
  journalisé et une nouvelle tentative a lieu une heure plus tard.

#### Hôtes sans proxy

`NO_PROXY` (ou la liste de l'écran **Proxy sortant**) donne, séparées par des virgules,
les destinations jointes **sans** le proxy :

| Entrée | Exemple | Effet |
|---|---|---|
| Domaine | `corp.example` ou `.corp.example` | Le domaine et tous ses sous-domaines (`sso.corp.example`) |
| Joker de sous-domaines | `*.corp.example` | Identique à `.corp.example` |
| Adresse IP | `10.0.0.5`, `[fd00::5]` | Cette adresse (un port éventuel, `10.0.0.5:8443`, est ignoré) |
| Tout | `*` | Aucune connexion ne passe par le proxy |

Une adresse ne s'applique qu'à une URL dont l'hôte **est** cette adresse IP
(`https://10.0.0.5/...`) : un nom d'hôte n'est jamais résolu. Pour contourner le proxy vers un
serveur interne joint par son nom, indiquez son domaine. Les plages d'adresses (CIDR,
`10.0.0.0/8`) ne sont pas prises en charge : dans `NO_PROXY`, une telle entrée ne correspond à
aucun hôte, et l'écran **Proxy sortant** la refuse. La boucle locale (`localhost`,
`127.0.0.0/8`, `::1`) est toujours jointe directement.

```bash
NO_PROXY=.corp.example,10.0.0.5
```

Le proxy peut aussi être choisi par un administrateur dans l'écran
[**Proxy sortant**](../../usage/index.md#ecrans) de l'interface web, pour les variables
non définies : `HTTPS_PROXY` (sinon `HTTP_PROXY`) et `NO_PROXY`, quand elles sont définies,
sont prioritaires sur les valeurs de l'écran. Elles s'appliquent au téléchargement suivant. L'écran **Base OSV** affiche l'état de
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

## Scan dans un pipeline (`security-review-ci scan-deps`)

Dans un pipeline, le [client de pipeline](../../advanced/architecture/ci.md)
envoie les fichiers de dépendances au contrôleur, qui les compare à sa base d'avis et, avec
`--save`, enregistre un rapport `dependency-scan` du projet. Le pipeline n'a besoin ni de la
base ni du paquet, seulement d'un [jeton `ci`](../../advanced/architecture/ci.md#jeton-ci-et-projets-visibles)
(ou `admin`) du projet :

```bash
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=...   # jeton ci limité à mon-projet
security-review-ci scan-deps package-lock.json requirements.txt \
    --fail-on high --require-database --project mon-projet --save
# code de sortie : 0 = ok, 1 = bloqué, 2 = erreur
```

- `--require-database` refuse le scan (code `2`, rien n'est enregistré) quand la vérification
  des vulnérabilités ne peut pas avoir lieu pour un fichier.
- Avec `--save`, l'utilisateur d'un jeton `ci` personnel est l'auteur du rapport, sinon
  `--author` enregistre le nom d'utilisateur du développeur avec lui (voir
  [auteur d'un rapport](../prompts-tools.md#auteur-dun-rapport)), `--repository`,
  `--branch` et `--commit` le contexte ; le libellé du jeton est enregistré comme appareil.
- Chaque fichier est limité au `SECREVIEW_MAX_DEPENDENCY_CHARS` du contrôleur, la requête à
  `SECREVIEW_MAX_SCAN_REQUEST_MB`. Les liens symboliques ne sont pas lus.

## Scan depuis un poste de travail (hook de commit)

Mise en place pas à pas, avec la revue par un agent : [Hooks de commit](../../getting-started/commit-hooks.md).

Un développeur lance le même `security-review-ci scan-deps` sur son poste, avec un
[jeton `mcp` ou `ci` personnel](../../usage/tokens.md#jetons-mcp-et-ci-personnels) créé dans
**Mon compte** : il atteint les projets que le développeur peut lire, et les fichiers sont
envoyés au contrôleur exactement tels qu'ils sont sur le disque. Le poste n'a pas besoin de
Python : installez le client avec uv (voir [Installation](../../advanced/architecture/ci.md#installation)).

```bash
uv tool install security-review-ci
export SECREVIEW_CONTROLLER_URL=https://secreview.example.com
export SECREVIEW_TOKEN=<personal mcp or ci token>
security-review-ci scan-deps uv.lock web/package-lock.json --project my-project --require-database
# code de sortie : 0 = ok, 1 = bloqué, 2 = erreur (contrôleur injoignable, jeton refusé...)
```

Hook de commit ([prek](https://prek.j178.dev) ou [pre-commit](https://pre-commit.com)), lancé
quand un manifeste ou un lockfile change. Avec `language: python`, le hook installe
`security-review-ci` dans son propre environnement : rien d'autre à installer. prek est un
binaire unique qui télécharge aussi le Python du hook (pre-commit a besoin d'un Python) :

```yaml
repos:
  - repo: local
    hooks:
      - id: scan-deps
        name: dependency scan
        entry: security-review-ci scan-deps --skip-unconfigured --require-database --project my-project
        language: python
        additional_dependencies: ["security-review-ci==X.Y.Z"] # version de votre contrôleur
        files: (^|/)(uv\.lock|requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json)$
```

Avec le client déjà installé (`uv tool install`), `language: system` le lance depuis le `PATH`.

`--skip-unconfigured` laisse passer le commit, avec un avertissement, quand
`SECREVIEW_CONTROLLER_URL` n'est pas défini (contributeurs sans contrôleur). Les deux variables
sont lues dans l'environnement uniquement, jamais dans le fichier `.env`.

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
- Pour un SBOM qui mélange des écosystèmes, la vérification est `performed` dès que l'un d'eux a
  des avis ; une note nomme les écosystèmes qui n'ont pas pu être vérifiés.
- Chaque composant est marqué `dev` ou non. Dans `pyproject.toml`, les extras nommées d'après
  le développement (`dev`, `test`, `docs`, `lint`...) et les `[dependency-groups]` sont `dev` ;
  les autres extras (`postgres`...) sont installées en production et restent des dépendances
  d'exécution.
- Règles d'hygiène `DEP-001` à `DEP-009` : versions non épinglées, URL / VCS, HTTP, index
  supplémentaire, `--trusted-host`, etc.
