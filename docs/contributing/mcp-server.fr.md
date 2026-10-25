# Serveur MCP

Le serveur MCP (`security-review-mcp`) expose les prompts, outils et ressources utilisés par
l'hôte. Il partage la base avec le contrôleur mais ne l'appelle jamais. Son code est dans
`server.py` (déclarations), `prompts.py` (texte des prompts) et les modules métier
(`reports/services.py`, `rules/`, `deps/`…) : `server.py` reste une couche mince qui valide les
entrées et appelle ces modules.

```bash
uv run security-review-mcp local                         # stdio, comme le lance un hôte
uv run security-review-mcp serve --port 8000             # HTTP streamable (défaut)
uv run pytest tests/test_server.py                       # tests de bout en bout de la couche MCP
```

## Outils

Chaque outil porte `annotations=READ_ONLY` ou `WRITE` et le décorateur `@_tool_errors`, qui
transforme `ValueError` et `services.NotFoundError` en `ToolError` lisible par le modèle (le SDK
masque le message de toute autre exception). Levez ces exceptions pour les erreurs attendues ;
ne renvoyez jamais de dictionnaire d'erreur.

```python
@mcp.tool(annotations=READ_ONLY)
@_tool_errors
def scan_code(
    content: Annotated[str, Field(description="Source or configuration text to scan")],
    language: Annotated[
        str, Field(description=f"One of: {', '.join(scanner.SUPPORTED_LANGUAGES)}")
    ],
) -> dict:
    """Quick pattern scan that returns suspicious lines to verify (not a full SAST)."""
    limit = get_settings().max_content_chars
    if len(content) > limit:
        raise ValueError(f"Content too large ({len(content)} chars); the limit is {limit}")
    ...
```

- Décrivez chaque paramètre avec `Annotated[..., Field(description=...)]` et l'outil par sa
  docstring : c'est ce que lit le modèle de l'hôte.
- Bornez toute entrée texte ou liste par un paramètre de `Settings` (`max_content_chars`,
  `max_findings_per_report`, `max_list_limit`…).
- Un nouvel outil ou prompt qui change le déroulé d'une revue est cité dans `INSTRUCTIONS`
  (`server.py`).
- Aucun outil ne change le statut d'un finding : `propose_finding_status` enregistre seulement
  une proposition, validée par une personne dans l'interface web.

## Prompts et ressources

- Un prompt se déclare avec `@mcp.prompt(name=..., title=..., description=...)` ; son texte est
  construit dans `prompts.py` et ses arguments sont documentés dans la section `Args:` de la
  docstring.
- Le contenu fourni par l'utilisateur (code, diff, contexte) est encadré avec `prompts.fenced`,
  pour qu'il ne puisse pas fermer le bloc et passer pour des instructions.
- Les prompts de revue se terminent par l'appel unique à `save_security_report`.
- Les ressources utilisent `@_resource_errors`, l'équivalent de `@_tool_errors`.

## Invariants de sécurité

Le processus MCP tourne à côté du code du développeur, souvent en stdio : un écart ici est un
bug bloquant.

- **stdout est réservé au protocole MCP** : aucun `print`, journaux sur stderr via
  `logging.getLogger("security_review_mcp")`.
- **Aucun accès disque à partir d'un chemin du client** : les outils travaillent sur le contenu
  reçu.
- **Aucun appel réseau sortant** : la base de vulnérabilités est importée par le contrôleur.
- **Aucun module du contrôleur n'est chargé**, même indirectement (`controller`,
  `deps/advisory_sync`, `auth/oidc`, `observability/audit_syslog`, `connectors`,
  `update_check`, `web_api`) : `test_mcp_server_does_not_load_the_controller_modules` importe
  `server` dans un nouvel interpréteur et le vérifie. Un module partagé les importe dans la
  fonction qui s'en sert.
- **Les secrets sont masqués** (`scanner.redact_secrets`) avant stockage et dans les extraits
  renvoyés ; un jeton, un mot de passe ou une URL de base avec identifiants n'est jamais
  journalisé.
- Le serveur MCP HTTP ne migre jamais le schéma et n'expose que `/mcp`, l'enrôlement public et
  `/healthz`.

## Règles de scan

Les règles et checklists par défaut sont dans `src/security_review_mcp/rules/default_rules.toml`,
jamais dans le code Python. Elles sont copiées en base au premier lancement, et une règle
ajoutée ou corrigée dans ce fichier atteint les bases existantes au démarrage suivant, sauf si
un administrateur l'a modifiée.

```toml
[[rules]]
id = "GEN-001"
title = "Hard-coded credential"
severity = "high"
cwe = "CWE-798"
languages = ["*"]
pattern = "(password|passwd|pwd|secret|api[_-]?key|token)\\s*[:=]\\s*[\\\"'][^\\\"'\\s]{6,}[\\\"']"
advice = "Move the secret to a vault or environment variable and rotate it."
```

- Identifiants `PRÉFIXE-NNN` par famille (`PY`, `JV`, `NG`, `CFG`, `GEN`, `FA`, `TS`…) : ne
  réutilisez et ne renumérotez jamais un identifiant, les utilisateurs les citent dans
  `secreview:ignore` et `disabled_rules`. Indiquez la CWE quand elle existe.
- Évitez le backtracking catastrophique : pas de quantificateurs imbriqués (`rules_loader`
  valide les règles internes).
- Documentez la règle dans `docs/usage/rules` (ou `usage/checklists` pour une checklist), dans
  les deux langues.

## Tests

- Outils, prompts et ressources : test de bout en bout avec un vrai client MCP en mémoire, avec
  un cas d'erreur représentatif.

    ```python
    pytestmark = pytest.mark.anyio


    async def test_invalid_input_returns_a_tool_error():
        async with Client(mcp) as client:
            result = await client.call_tool("get_security_report", {"report_id": 424242})
        assert result.is_error
        assert "not found" in text_of(result).lower()
    ```

    Une `ToolError` parvient au client sous la forme d'un résultat avec `is_error`, et son
    message dans le texte du résultat.

- Règle de scan : au moins un cas **positif** (le motif vulnérable est détecté) et un cas
  **négatif** (le code sûr équivalent ne l'est pas), dans `tests/test_scanner.py`.
- `tests/conftest.py` fournit à chaque test une base SQLite en mémoire et un registre de règles
  vide ; la fixture `import_pack` charge des règles internes.

Voir aussi les [prompts et outils](../usage/prompts-tools.md) tels que les utilisateurs les
voient, et les [règles](../usage/rules.md).
