# Third-party connectors

A connector can be added for any other tool: a vulnerability register, a GRC platform, an
internal tracker... It works like the built-in connectors: same switch, connection, destinations
and guarantees (see [Connectors](index.md)).

## Installing a connector

A third-party connector is a Python package that the operator installs next to the Controller server,
then **allows** explicitly: installing it is not enough. The commands are in
[Connectors in detail](../../advanced/connectors.md#third-party-connectors); writing one is
described in [Writing a connector](../../contributing/connectors.md).

Once allowed, it shows on the **Connectors** screen as a card marked **Third-party**, off until
an administrator enables it.

!!! warning
    A connector runs inside the Controller server, with its rights: install and allow only code you
    trust, like any dependency.
