# Web interface (Angular)

The Angular 22 application (signals, zoneless, Bootstrap 5) is in `web/`. Its build is written
into `src/security_review_mcp/webui/`, from where the controller serves it on `/ui/` and the
wheel embeds it.

```bash
cd web
npm ci
npm run build                 # production build (to redo before uv build)
npm start                     # dev server on http://localhost:4200/ui/
npm run format                # Prettier
```

`npm start` forwards `/api` to `http://127.0.0.1:8080` (`web/proxy.conf.json`): start the
controller in parallel with `security-review-controller serve --port 8080`, or use the VS Code
configuration **Controller (debug: FastAPI + Angular)**, which starts both under the debugger: every save
of a file of `web/src/` reloads the page (styles and templates without a full reload), and the
breakpoints set in the `.ts` files are honored. In the devcontainer, Chrome is opened on the
local workstation and port 4200 is forwarded automatically.

## Layout of `web/src/app/`

| Folder | Content |
|---|---|
| `core/` | Services (API calls, session, triage), guards, interceptors, models of the API (`models/api.models.ts`), translations (`i18n/`) |
| `features/` | One folder per screen (`reports`, `rules`, `tokens`, `access`…), loaded by `app.routes.ts` |
| `shared/` | Reusable components and utilities without business logic |
| `layout/` | Shell of the application (menu, header) |

## Code conventions

- **Components**: template and styles in separate files. A feature with several screens has one
  folder per component (`features/access/role-list/`); its shared files (styles, base class,
  error messages) stay at the root of the feature.
- **Forms**: the input forms use the Signal Forms (`form()`, `[formField]`, validators with a
  translated message); the list filters and the dynamic lists of checkboxes stay plain event
  handlers.
- **HTTP calls**: through `rxResource` for the data of a screen, or `await
  firstValueFrom(...)` for an action; no `.subscribe()` in the components.
- **State**: `signal()` and `computed()`; a value derived from another one but still editable (a
  form filled with the loaded settings) is a `linkedSignal()`. `effect()` is kept for real side
  effects (document attributes, local storage, timers), never to copy a signal into another. A
  service exposes its signals with `asReadonly()` and changes them through named methods.
- **Folders**: `shared/` holds reusable components without business logic: they get their data
  through inputs and report through outputs, never through a business service of `core/` (the
  finding card emits the decision, `TriageService` saves it). The shell of the application is
  `layout/`.
- **Templates**: host bindings in `host: {}` (no `@HostListener`); a message that explains why a
  field is invalid is linked to it with `aria-describedby`.
- **Tables**: `app-table-controls` holds the search and the filters; the sort is chosen on the
  column headers (`<th [appSortHeader]="sort" sortKey="name">`), with a `TableSort` named after
  the table (`shared/utils/table-sort.ts`) that the browser remembers under
  `secreview.sort.<name>`.
- **Colors**: Bootstrap variables (`var(--bs-…)`) or the design tokens of `styles.css`
  (`--app-…`), never a color written in a component, so that the light and dark themes work.

## Interface translations

The interface is translated into English, French and Spanish by an in-house service
(`web/src/app/core/i18n/`), without any extra dependency. Each screen has its catalog in
`core/i18n/messages/<screen>.ts`, declared in `messages/index.ts`, with its messages in the three
languages:

```ts
export const tokens = defineMessages({
  en: { 'tokens.created': 'Token “{label}” created.' },
  fr: { 'tokens.created': 'Jeton « {label} » créé.' },
  es: { 'tokens.created': 'Token «{label}» creado.' },
});
```

- In a template: `{{ 'tokens.title' | t }}`, or with parameters
  `{{ 'tokens.created' | t: { label: name } }}`.
- In the code: `I18nService.translate(...)` (confirmations, messages of the Signal Forms
  validators through `message: () => ...`). A message shown later (success, error) is kept as
  `msg(key, parameters)` and translated in the template, so that it follows a change of language.
- The title of the routes is a key, translated by `I18nTitleStrategy`.
- A link to the documentation is a circled question mark next to the title:
  `<app-help-link topic="tokens" />`. The topics, with their page and the anchor of the heading
  in English and in French, are in `core/constants/doc-links.ts`; check them after renaming a
  heading of `docs/`.

The keys are typed: an unknown key, or a key missing in one of the three languages, fails
`npm run build`.

## Checks

```bash
npm --prefix web run build                                   # also checks the i18n keys
npm --prefix web exec --no -- prettier --check <changed files>
```

A change of the audit catalog (`core/i18n/messages/audit.ts`) is also checked by
`uv run pytest tests/test_audit.py`: every kind of audit event needs its label in the three
languages. The REST routes called by the interface are described in
[Controller (FastAPI)](controller.md).
