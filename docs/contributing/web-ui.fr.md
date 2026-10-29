# Interface web (Angular)

L'application Angular 22 (signaux, zoneless, Bootstrap 5) est dans `web/`. Sa build est écrite
dans `src/security_review_mcp/webui/`, d'où le serveur Controller la sert sur `/ui/` et le wheel l'embarque.

```bash
cd web
npm ci
npm run build                 # build de production (à refaire avant uv build)
npm start                     # serveur de dev sur http://localhost:4200/ui/
npm run format                # Prettier
```

`npm start` redirige `/api` vers `http://127.0.0.1:8080` (`web/proxy.conf.json`) : lancez le
serveur Controller en parallèle avec `security-review-controller serve --port 8080`, ou utilisez la
configuration VS Code **Controller (debug: FastAPI + Angular)**, qui démarre les deux sous le débogueur : chaque enregistrement d'un
fichier de `web/src/` recharge la page (styles et templates sans rechargement complet), et les
points d'arrêt posés dans les fichiers `.ts` sont pris en compte. Dans le devcontainer, Chrome
est ouvert sur le poste local et le port 4200 est redirigé automatiquement.

## Organisation de `web/src/app/`

| Dossier | Contenu |
|---|---|
| `core/` | Services (appels à l'API, session, triage), guards, intercepteurs, modèles de l'API (`models/api.models.ts`), traductions (`i18n/`) |
| `features/` | Un dossier par page (`reports`, `rules`, `tokens`, `access`…), chargé par `app.routes.ts` |
| `shared/` | Composants et utilitaires réutilisables, sans logique métier |
| `layout/` | Coque de l'application (menu, en-tête) |

## Conventions de code

- **Composants** : template et styles dans des fichiers séparés. Une fonctionnalité à plusieurs
  pages a un dossier par composant (`features/access/role-list/`) ; ses fichiers partagés
  (styles, classe de base, messages d'erreur) restent à la racine de la fonctionnalité.
- **Formulaires** : les formulaires de saisie utilisent les Signal Forms (`form()`,
  `[formField]`, validateurs avec un message traduit) ; les filtres de liste et les listes
  dynamiques de cases à cocher restent de simples gestionnaires d'événements.
- **Appels HTTP** : par `rxResource` pour les données d'une page, ou `await
  firstValueFrom(...)` pour une action ; pas de `.subscribe()` dans les composants.
- **État** : `signal()` et `computed()` ; une valeur dérivée d'une autre mais modifiable (un
  formulaire rempli avec les réglages chargés) est un `linkedSignal()`. `effect()` est réservé aux
  vrais effets de bord (attributs du document, stockage local, minuteries), jamais pour recopier
  un signal dans un autre. Un service expose ses signaux avec `asReadonly()` et les modifie par
  des méthodes nommées.
- **Dossiers** : `shared/` contient des composants réutilisables sans logique métier : ils
  reçoivent leurs données par des entrées et répondent par des sorties, jamais par un service
  métier de `core/` (la fiche d'un finding émet la décision, `TriageService` l'enregistre). La
  coquille de l'application est `layout/`.
- **Templates** : liaisons de l'hôte dans `host: {}` (pas de `@HostListener`) ; un message qui
  explique pourquoi un champ est invalide lui est relié par `aria-describedby`.
- **Tableaux** : `app-table-controls` porte la recherche et les filtres ; le tri se choisit sur les
  en-têtes de colonne (`<th [appSortHeader]="sort" sortKey="name">`), avec un `TableSort` nommé
  d'après le tableau (`shared/utils/table-sort.ts`) que le navigateur mémorise sous
  `secreview.sort.<nom>`.
- **Couleurs** : variables Bootstrap (`var(--bs-…)`) ou jetons de `styles.css` (`--app-…`),
  jamais une couleur écrite dans un composant, pour que les thèmes clair et sombre fonctionnent.

## Traductions de l'interface

L'interface est traduite en anglais, français et espagnol par un service maison
(`web/src/app/core/i18n/`), sans dépendance supplémentaire. Chaque page a son catalogue dans
`core/i18n/messages/<page>.ts`, déclaré dans `messages/index.ts`, avec ses messages dans les trois
langues :

```ts
export const tokens = defineMessages({
  en: { 'tokens.created': 'Token “{label}” created.' },
  fr: { 'tokens.created': 'Jeton « {label} » créé.' },
  es: { 'tokens.created': 'Token «{label}» creado.' },
});
```

- Dans un template : `{{ 'tokens.title' | t }}`, ou avec des paramètres
  `{{ 'tokens.created' | t: { label: name } }}`.
- Dans le code : `I18nService.translate(...)` (confirmations, messages des validateurs Signal
  Forms via `message: () => ...`). Un message affiché plus tard (succès, erreur) est gardé sous la
  forme `msg(clé, paramètres)` et traduit dans le template, pour suivre un changement de langue.
- Le titre des routes est une clé, traduite par `I18nTitleStrategy`.
- Un lien vers la documentation est un point d'interrogation cerclé à côté du titre :
  `<app-help-link topic="tokens" />`. Les sujets, avec leur page et l'ancre du titre en anglais
  et en français, sont dans `core/constants/doc-links.ts` ; vérifiez-les après avoir renommé un
  titre de `docs/`.

Les clés sont typées : une clé inconnue, ou absente d'une des trois langues, fait échouer
`npm run build`.

## Vérifications

```bash
npm --prefix web run build                                   # vérifie aussi les clés i18n
npm --prefix web exec --no -- prettier --check <changed files>
```

Une modification du catalogue de l'audit (`core/i18n/messages/audit.ts`) est aussi vérifiée par
`uv run pytest tests/test_audit.py` : chaque type d'événement d'audit doit avoir son libellé
dans les trois langues. Les routes REST appelées par l'interface sont décrites dans
[Serveur Controller (FastAPI)](controller.md).
