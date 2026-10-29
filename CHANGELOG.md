# Changelog

## [9.0.0](https://github.com/cyr-ius/security-review/compare/v8.1.2...v9.0.0) (2026-10-29)


### ⚠ BREAKING CHANGES

* the mcp_tokens.create permission and the mcp-user role are removed; use SECREVIEW_PERSONAL_TOKENS_ENABLED instead.

### Features

* add --version to security-review-mcp, security-review-controller and security-review-ci ([294d4f3](https://github.com/cyr-ius/security-review/commit/294d4f3455204023f633279e12136df4c18c57bd))
* add the projects.autojoin permission and block it per project ([5436ce5](https://github.com/cyr-ius/security-review/commit/5436ce50a79524a17478645bae180ec5d25fde27))
* **config:** read the public URL of the Controller server from SECREVIEW_PUBLIC_URL ([a321da8](https://github.com/cyr-ius/security-review/commit/a321da8a4b9d9c05b8d123909a108b19d11da87d))
* filter findings, risk acceptances and reports on several values ([46f3294](https://github.com/cyr-ius/security-review/commit/46f3294ed49ba5eae315f7eee7457b7dccef3e4b))
* log the version when the MCP and Controller servers start ([d96fea7](https://github.com/cyr-ius/security-review/commit/d96fea7eea52aeedff227db9bbc423daefcc337e))
* replace the mcp_tokens.create permission with SECREVIEW_PERSONAL_TOKENS_ENABLED ([dde2cac](https://github.com/cyr-ius/security-review/commit/dde2cacb37db9c7df27b581594247539ba8d9da1))
* **ui:** add a Review section to the sidebar with findings and risk acceptances ([ab4bce1](https://github.com/cyr-ius/security-review/commit/ab4bce13c9d12c99a3dcebc3105cf1ed41a4c59c))
* **ui:** retry automatically on the Backend unavailable page ([316c6ed](https://github.com/cyr-ius/security-review/commit/316c6ed999aadbc1efaa6fa2a4eb2349e7e534ae))
* **ui:** show the MCP endpoint field in the OAuth settings list ([92ab5ba](https://github.com/cyr-ius/security-review/commit/92ab5ba2b9c1238e3f8f9189a2f80699036b4e18))


### Bug Fixes

* create the project group when a token reaching every project requests a project ([07523ea](https://github.com/cyr-ius/security-review/commit/07523ea4541e90bf78db406b4cdc9599debd1d57))


### Documentation

* align the English usage pages and fix the French ones ([98e7e32](https://github.com/cyr-ius/security-review/commit/98e7e3223b7cf919c873d151ec8e24284b8d798a))
* call the views of the web interface pages instead of screens ([ec2c12c](https://github.com/cyr-ius/security-review/commit/ec2c12c436c58e2f5b993e85cb349fcf31fb694d))
* document the MCP prompts, tools and resources and split the two codebase analysis modes ([9399b04](https://github.com/cyr-ius/security-review/commit/9399b040c4da9868135bd35851ddcde40829c4f5))
* show the project logo in the documentation header ([316348e](https://github.com/cyr-ius/security-review/commit/316348e4b475e89782962d2e128adb0899e44e61))
* Update index.fr.md ([2f0fb4a](https://github.com/cyr-ius/security-review/commit/2f0fb4abe858b6c44df54b145d4b05b35e2b5426))
* Update projects.fr.md ([99da6ff](https://github.com/cyr-ius/security-review/commit/99da6ff9c6d89f7f73e4e6797430b1076bce131d))
* Update triage.fr.md ([5076551](https://github.com/cyr-ius/security-review/commit/5076551ae99c3a339370400edd95c1707680e9d1))

## [8.1.2](https://github.com/cyr-ius/security-review/compare/v8.1.1...v8.1.2) (2026-10-28)


### Bug Fixes

* **ci:** merge master back into dev after each release ([5aa749e](https://github.com/cyr-ius/security-review/commit/5aa749e46217f4bf5666c171cd4bfdffd713d339))
* **ci:** publish the GitHub release at the end of the publication ([c7b5501](https://github.com/cyr-ius/security-review/commit/c7b5501b8ee70f0e75942363ae599238b95f3f6b))
* **ci:** publish the GitHub release last and sync dev after a release ([ec5fd6b](https://github.com/cyr-ius/security-review/commit/ec5fd6b26191fad8afe270f40f4c92eae728160b))

## [8.1.1](https://github.com/cyr-ius/security-review/compare/v8.1.0...v8.1.1) (2026-10-28)


### Bug Fixes

* **ci:** make Release Please releases buildable and published ([3b0d626](https://github.com/cyr-ius/security-review/commit/3b0d626531217e40b3178c39aaf9ad5f0fbea340))
* **ci:** start the publication when Release Please creates a release ([83268cc](https://github.com/cyr-ius/security-review/commit/83268cc16e2a65f869028983a4694d2aecf04839))


### Documentation

* **agents:** describe the releases made by Release Please ([44fc4b4](https://github.com/cyr-ius/security-review/commit/44fc4b473ea9939c4500dbd5d8cb13caf0c8c637))

## [8.1.0](https://github.com/cyr-ius/security-review/compare/v8.0.0...v8.1.0) (2026-10-28)


### Features

* **mcp:** add the --database-url option to local and serve ([af2ca0c](https://github.com/cyr-ius/security-review/commit/af2ca0c3d14e5fc4e87edf8b6ef804c8fbbd2b77))


### Bug Fixes

* **ci:** Rename flow to Release Please ([48abd16](https://github.com/cyr-ius/security-review/commit/48abd16240670c101a0d24390a9b9d216f1e56f7))
* **code:** remove db upgrade call ([b0a87d5](https://github.com/cyr-ius/security-review/commit/b0a87d586c4fe2fc8f51028e1a476c17ba67640f))
* **i18n:** update message for group name ([559b21c](https://github.com/cyr-ius/security-review/commit/559b21cb66e43184c53e475583dd8829c1d7c634))
* **i18n:** update message for proxyHelp ([27fad21](https://github.com/cyr-ius/security-review/commit/27fad2108650996c3e9c321fd7cf77436869316f))
* **oauth:** drop refused redirect URIs instead of refusing the client ([a2cf9ff](https://github.com/cyr-ius/security-review/commit/a2cf9ffe98f3168b7a902f2fe97e8a1383233752))
* **vscode:** add fictive secret key ([7521804](https://github.com/cyr-ius/security-review/commit/75218049cc88cd4819654ef7551a965a22a85575))


### Documentation

* fix the links to the removed internal CA section ([8eee501](https://github.com/cyr-ius/security-review/commit/8eee501d913163c349e8a1570a632b0084429a97))
* rework the SQLite or PostgreSQL section of the database page ([bb2f2f4](https://github.com/cyr-ius/security-review/commit/bb2f2f4bd6879f3a933267c2656abf45c0e5ca5b))
* update documentations ([bc6b073](https://github.com/cyr-ius/security-review/commit/bc6b073ef17372c354c878129a13347dd94f1103))
* Update tls.fr.md ([951845b](https://github.com/cyr-ius/security-review/commit/951845b03016cbbf91bc733af84f8c363f4e8481))
* Update tls.md ([c55b0af](https://github.com/cyr-ius/security-review/commit/c55b0af7867394bf5fd8006d8fe42ba96f223418))
