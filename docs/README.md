# Documentation

Start with the [operator guide](operator-guide.md) to configure and run the
exporter, or the [MVP acceptance record](mvp-acceptance.md) to see the tested
behavior and evidence boundary.

| Area | Purpose |
| --- | --- |
| [`product-specs/`](product-specs/) | User-visible behavior and compatibility contract |
| [`design-docs/`](design-docs/) | Component, protocol-state, and verification designs |
| [`decisions/`](decisions/) | Accepted architectural decisions 0001–0006 |
| [`compatibility/`](compatibility/) | Receiver schema, field mapping, token vocabulary, and profiles |
| [`research/`](research/) | Concise primary-source and tool-version provenance |
| [`operator-guide.md`](operator-guide.md) | Configuration, deployment, transport, and troubleshooting |
| [`release.md`](release.md) | Alpha status, publication steps, and release limits |
| [`ci.md`](ci.md) | Local checks and the checked-in workflow's evidence boundary |

Generated reference material is kept next to the component metadata. Run
`make check test` after documentation or configuration changes.
