# Third-party connectors

A Python package can add a connector for any other system: a vulnerability register, a GRC
platform, an internal tracker... It gets the same switch, connection, destinations and
guarantees as the built-in connectors (see [Connectors](index.md)).

## Installing a connector

A connector published by a Python package (entry point of the group
`security_review_mcp.connectors`) is installed next to the controller, then **allowed** by its
entry point name: installing a package is not enough.

```bash
uv pip install secreview-acme-connector         # in the image or the environment of the controller
SECREVIEW_CONNECTORS_PLUGINS=acme               # comma separated
SECREVIEW_ACME_URL=https://risk.acme.example/api
SECREVIEW_ACME_API_KEY=...
```

The controller loads the allowed connectors at start and refuses to start if one is missing,
written for another version of the API, or declares a variable of the server itself
(`SECREVIEW_<KIND>_<FIELD>` must not be an existing setting). The **Connectors** screen shows it
as a card marked **Third-party**, off until switched on. A connector runs in the controller with
its rights: only install and allow code you trust, like any dependency.
