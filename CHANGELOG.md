# Changelog

## [11.4.0](https://github.com/cyr-ius/security-review/compare/v11.3.0...v11.4.0) (2026-11-12)


### Features

* add 15 more default OpenGrep rules ([7f08e55](https://github.com/cyr-ius/security-review/commit/7f08e5512302adc09320bd7230e58caec19af978))
* add 17 default OpenGrep rules ([7c86d62](https://github.com/cyr-ius/security-review/commit/7c86d626f028c38c03bbbf4dbb3f55fc34ba7257))
* add 18 more default OpenGrep rules ([f660cd2](https://github.com/cyr-ius/security-review/commit/f660cd26498d360412174f9d8df86560116f7ad6))
* cover more Python sources and fix false positives of the default OpenGrep rules ([7556fea](https://github.com/cyr-ius/security-review/commit/7556fea63600bdb4f2b664a570e0c71114a78970))
* follow Python taint through containers and pathlib bases ([0a0614b](https://github.com/cyr-ius/security-review/commit/0a0614b190f3b1133d2dce2b84fb2580f30109a6))
* follow the taint across the functions of a file with OpenGrep ([bc1f819](https://github.com/cyr-ius/security-review/commit/bc1f819a6a6478f6973690f6032d3d70d16b1a3a))
* improve OWASP Benchmark detection of the default OpenGrep rules ([171ddab](https://github.com/cyr-ius/security-review/commit/171ddab3d9a61365d1e2e6e45a16e70d9511309b))
* raise the detection rate of the default OpenGrep rules ([850b43a](https://github.com/cyr-ius/security-review/commit/850b43ab41912ddef57e091fbe27746401241eb9))
* widen the Python taint sources and sinks of the default OpenGrep rules ([eef4724](https://github.com/cyr-ius/security-review/commit/eef472445a5522db4cf9103f0585529c19ba7156))


### Bug Fixes

* classify PY-007 as a weak hash and widen the Python weak hash and random rules ([94c0d5f](https://github.com/cyr-ius/security-review/commit/94c0d5f29eb78d1a18f2ed90595e87f768c073cf))
* reduce false positives of 15 default OpenGrep rules ([5a2e534](https://github.com/cyr-ius/security-review/commit/5a2e5346cd934a14545fd3466d7c0ca9aac4c367))


### Documentation

* publish the OWASP Benchmark results and describe the scan as a SAST ([d15d92e](https://github.com/cyr-ius/security-review/commit/d15d92effb30851440ffde32f2713749a9109de8))

## [11.3.0](https://github.com/cyr-ius/security-review/compare/v11.2.0...v11.3.0) (2026-11-09)


### Features

* decide_finding_status applies the developer's decision in local mode ([bb4a45a](https://github.com/cyr-ius/security-review/commit/bb4a45aa14f215c1734e80d19c85e5aab3096840))
* export_findings_report tool for a Markdown findings report ([9fd0977](https://github.com/cyr-ius/security-review/commit/9fd0977a1e0acdf3df1b440b649595ff5e1aee0c))


### Documentation

* OAuth and local-mode quick starts, uvx-first local mode page ([59ac1ec](https://github.com/cyr-ius/security-review/commit/59ac1ecd5c7b0c7f462a82084aeaa39e6ea01e38))

## [11.2.0](https://github.com/cyr-ius/security-review/compare/v11.1.0...v11.2.0) (2026-11-07)


### Features

* **findings:** search the findings by text on the findings pages ([858f4f5](https://github.com/cyr-ius/security-review/commit/858f4f5ec1d61d6c228062ee0f049769cacf9fca))
* **web:** drop the Reports entry from the sidebar ([3a98002](https://github.com/cyr-ius/security-review/commit/3a98002df54bbe66257865a025feee84c59dbf0e))
* **web:** global search in the top bar ([9b5fa13](https://github.com/cyr-ius/security-review/commit/9b5fa1315a459f7a0da388b779935709954229a1))
* **web:** move the Reports entry under Risk acceptances in the sidebar ([e3e2641](https://github.com/cyr-ius/security-review/commit/e3e264111e994428ec066b9073bd406b336ba63e))
* **web:** multiple-choice filters with search and select all everywhere ([8d6b307](https://github.com/cyr-ius/security-review/commit/8d6b30761c5229872f411f48ec3de35ec9c8a622))
* **web:** search projects, inside a report, with filters and live results ([65bb9cd](https://github.com/cyr-ius/security-review/commit/65bb9cdcdabc52f7ab461e6958d05f6d71d3dbdb))


### Bug Fixes

* **triage:** bulk decision no longer capped by the page size ([19d2c4f](https://github.com/cyr-ius/security-review/commit/19d2c4f6007d9798ed5a1d9d05586235c6f12dbc))
* **web:** clearer examples in the help of the top bar search ([be9c967](https://github.com/cyr-ius/security-review/commit/be9c9671ad0472c2a2c4da53d4ba48ba6cb0797c))
* **web:** one card per finding on the report page ([bc290a7](https://github.com/cyr-ius/security-review/commit/bc290a7afd0f84da4b1ca59fb58ede004fd9abf5))
* **web:** small search field on the findings page ([b92f3d6](https://github.com/cyr-ius/security-review/commit/b92f3d67f44e40a65ea65b66800ee52dc0d1edb1))

## [11.1.0](https://github.com/cyr-ius/security-review/compare/v11.0.0...v11.1.0) (2026-11-07)


### Features

* **advisories:** choose the downloaded OSV ecosystems in the web interface ([4ff73a7](https://github.com/cyr-ius/security-review/commit/4ff73a717576d7d75d237fbaa3128f4e8acd7990))
* **mcp:** delegate scan_code to the Controller server ([4de0c39](https://github.com/cyr-ius/security-review/commit/4de0c39fbc9ee6f81b7ddc2b43786e505765e475))
* **settings:** delegate scan_code to the Controller server address from the web interface ([fd0d4da](https://github.com/cyr-ius/security-review/commit/fd0d4da1ff9fcc89e3a49a664a61e2521b9bf79f))
* **triage:** record one decision on several findings at once ([a7f8a0d](https://github.com/cyr-ius/security-review/commit/a7f8a0dc534514c268ec94a440d9df4c033daef1))
* **web:** show the pending OpenGrep rule proposals in the menu ([3045248](https://github.com/cyr-ius/security-review/commit/3045248f27eef71cdb43f4fb55d7b0acf04e1a83))


### Bug Fixes

* **opengrep:** give the scan_code fragments their own scan slots ([8b98356](https://github.com/cyr-ius/security-review/commit/8b983560cc0c064d571143d7dabd715f98655cb7))
* **opengrep:** refuse a proposed rule that duplicates an existing one ([243823e](https://github.com/cyr-ius/security-review/commit/243823ef4e53a3811fd858542bcf480f14961b09))

## [11.0.0](https://github.com/cyr-ius/security-review/compare/v10.0.1...v11.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* **rules:** scan_code no longer follows data flows, and the rule ids above are no longer reported; data flows are only followed by OpenGrep during a scan of the codebase.

### Features

* **docker:** choose the process with the controller or mcp command ([0581b48](https://github.com/cyr-ius/security-review/commit/0581b48dce1932e570f3b11058ae87c3fccca21f))
* **docker:** publish -opengrep and -stdio image variants ([c2a55a6](https://github.com/cyr-ius/security-review/commit/c2a55a6c71d2e13b8d03231d0f2d056d7713a2e5))
* **opengrep:** add a Rust taint rule from request extractors to SQL queries ([7f40765](https://github.com/cyr-ius/security-review/commit/7f407658a61c9a7cb32213f33c6fb3b03760f7bd))
* **opengrep:** add controller settings ([7b169ae](https://github.com/cyr-ius/security-review/commit/7b169ae9ee485964eaf77d06fefd385b17408131))
* **opengrep:** add navigation and localized labels ([114bee9](https://github.com/cyr-ius/security-review/commit/114bee99e836e08b7ddff1e9105a69c47abc47df))
* **opengrep:** add OpenGrep rules navigation and translations ([2d29c4a](https://github.com/cyr-ius/security-review/commit/2d29c4a5099bd1a2109b9fc6433ea06cdeb9083d))
* **opengrep:** add OpenGrep scan adapter ([bfa3743](https://github.com/cyr-ius/security-review/commit/bfa37432c688f8bb4e967df500ba2d79fe669c57))
* **opengrep:** add OpenGrep scan adapter ([7d61652](https://github.com/cyr-ius/security-review/commit/7d616529c3f049aaaa700c842e31015a73386b8a))
* **opengrep:** add secure YAML rule management API ([8c47439](https://github.com/cyr-ius/security-review/commit/8c474395470e41c5795c1434a797c1be59ac4383))
* **opengrep:** add secure YAML rule management API ([1c2a2a5](https://github.com/cyr-ius/security-review/commit/1c2a2a51d0151d215c42f5fadc2041f013cd8ec4))
* **opengrep:** add typed API client and Angular route ([1ee51e6](https://github.com/cyr-ius/security-review/commit/1ee51e6a70a7d742852b4bc97cdc8d3766cd8ab4))
* **opengrep:** add typed API client and route ([efb18c7](https://github.com/cyr-ius/security-review/commit/efb18c7fc788d24f3a0ad9c88547cce178e9e484))
* **opengrep:** add YAML rule editor to Angular UI ([43ada09](https://github.com/cyr-ius/security-review/commit/43ada09058b3777cedc8cb4ccef88cf4aa56c05a))
* **opengrep:** add YAML rule editor to Angular UI ([7a8c189](https://github.com/cyr-ius/security-review/commit/7a8c189f4412fe3d891335e75242d1f9394edbed))
* **opengrep:** bundle default OpenGrep rules with an install command ([7a358a4](https://github.com/cyr-ius/security-review/commit/7a358a45f927e514bc2bea5717cc5a3870db1656))
* **opengrep:** install the default rules at start-up while OpenGrep is enabled ([2fb8674](https://github.com/cyr-ius/security-review/commit/2fb8674f8df97429a24472e3fafb668c62553692))
* **opengrep:** integrate engine into codebase scans ([1d688dc](https://github.com/cyr-ius/security-review/commit/1d688dc1f294081190d3a7810908547ddad66e0c))
* **opengrep:** let review agents propose OpenGrep rules for human approval ([0e9330e](https://github.com/cyr-ius/security-review/commit/0e9330e8337d6b054e28da8271cf24bd19ea0943))
* **rules:** replace the Tree-sitter flow analyses with OpenGrep ([0a3ed61](https://github.com/cyr-ius/security-review/commit/0a3ed61805197b77ce5538c620ade324b5cfd859))


### Bug Fixes

* **ci:** lint file ([e15afad](https://github.com/cyr-ius/security-review/commit/e15afad822d270d3116acbd61b6337c7d5b45271))
* **devcontainer:** mount workspace at /workspaces/security-review ([33ff202](https://github.com/cyr-ius/security-review/commit/33ff2027e4e9d5f26ca491f54788ea24741e9cd6))
* **docker:** drop the -stdio image variant ([2486a4a](https://github.com/cyr-ius/security-review/commit/2486a4acb19c4a7affebb44c487b07182528e5ba))
* **docker:** ship only the extracted OpenGrep bundle ([d1cff3d](https://github.com/cyr-ius/security-review/commit/d1cff3d466dd6036888ce4a937643e0ed99f909d))
* **doc:** rename to security-review ([a407896](https://github.com/cyr-ius/security-review/commit/a4078960b4fc2f663e4012741822b00573c73e2b))
* **doc:** rename to security-review ([1bcff25](https://github.com/cyr-ius/security-review/commit/1bcff25c6fd664b5d24dadbe52440595ed99ed35))
* list the users who have every project among the members of a project ([145408e](https://github.com/cyr-ius/security-review/commit/145408e6a2db047d412c917c43f7405e19e9fc6e))
* name the product Security Review (short name secreview) ([94b61c3](https://github.com/cyr-ius/security-review/commit/94b61c301068665d56145c71fbb936dcbd470414))
* **opengrep:** bound concurrent scans and fix rule id ReDoS ([89048f4](https://github.com/cyr-ius/security-review/commit/89048f4f0f546ad0db848aad0581a7b86476fd3a))
* **opengrep:** normalize relative result paths ([9f77b45](https://github.com/cyr-ius/security-review/commit/9f77b45cc24d9ff9d23599abf5ef6040c41a8e7f))
* **opengrep:** resolve configured rules directory ([427d27e](https://github.com/cyr-ius/security-review/commit/427d27e4707d4d3d023eced1da6b7fc5b00ee244))
* **opengrep:** type UI notices and complete translations ([9cb1930](https://github.com/cyr-ius/security-review/commit/9cb1930324af2785892f2f8eb5bf5fa3e4ef7583))
* **opengrep:** use UTC timestamp consistently ([e76b3b8](https://github.com/cyr-ius/security-review/commit/e76b3b8d5b95ca2b3707a4b0bf264d8d3ea4caf1))
* report a dependency issue once across a dependency review and a dependency scan ([7cb6288](https://github.com/cyr-ius/security-review/commit/7cb628856f3fe6d5108cf0061303e8f7bed1b9ec))


### Documentation

* **opengrep:** add engine page to documentation navigation ([0ded507](https://github.com/cyr-ius/security-review/commit/0ded5074c2ce60356da9a327f58f7810e6a47403))
* **opengrep:** add French engine documentation ([23e855b](https://github.com/cyr-ius/security-review/commit/23e855b4ae2b297180188dc829fba71057980905))
* **opengrep:** document optional static analysis engine ([3b7a99c](https://github.com/cyr-ius/security-review/commit/3b7a99c0ace3496c792f076be3940e46f6bd596f))
* **opengrep:** document web rule management ([d360f86](https://github.com/cyr-ius/security-review/commit/d360f8654e3d4353df6361d8e0a25ee68ad148b7))
* present Security Review as the MCP server for AI-assisted security code review ([c2840cb](https://github.com/cyr-ius/security-review/commit/c2840cb34f78c7ccae4bb9e2b78151f170fcd3bf))

## [10.0.1](https://github.com/cyr-ius/security-review/compare/v10.0.0...v10.0.1) (2026-10-30)


### Bug Fixes

* bind OAuth grants to the MCP endpoint they were issued for ([05bf6e4](https://github.com/cyr-ius/security-review/commit/05bf6e42b2d7e735c58fa58678733299c7171cae))
* count the projects of an automatic join once added, the user locked ([c83476f](https://github.com/cyr-ius/security-review/commit/c83476f97db864cf5b96842a2ec023f41a67df3a))
* limit and gate the project creations of tokens that reach every project ([5e83281](https://github.com/cyr-ius/security-review/commit/5e83281139fb1d3a88d17f3021a9edf9b0547824))
* refuse a replacement of project members or OIDC mappings from a stale page ([805be4b](https://github.com/cyr-ius/security-review/commit/805be4b499d71688e9ef33cdb546d229ca985c11))
* require users.manage to block or allow the autojoin of a project ([d0112b4](https://github.com/cyr-ius/security-review/commit/d0112b40a423875ba10ae59ecb0b79f3e3946bd8))


### Documentation

* fix the findings left in the docs, docstrings and launch configuration ([8eb6a7c](https://github.com/cyr-ius/security-review/commit/8eb6a7cf58a351cbc8b8408602cdd8aa54729be6))

## [10.0.0](https://github.com/cyr-ius/security-review/compare/v9.0.0...v10.0.0) (2026-10-30)


### ⚠ BREAKING CHANGES

* an account that only holds reports.read can no longer save reports or propose a status through its agent. Revision 0040 adds reports.write wherever reports.read is held, so existing agents keep working; remove it from the accounts that should only read.
* roles no longer accept reports.read or findings.triage; the reader role is removed; the user, project member, token and OIDC mapping APIs take per-project permissions.
* the groups are removed: the /groups routes, the group_ids fields of the users (replaced by role_ids and projects), the `group` command (replaced by `role`), `user set-groups` (replaced by `user set-access` with --role and --project) and SECREVIEW_OIDC_DEFAULT_GROUP.

### Features

* add rules.read and standards.read permissions ([76f9ecc](https://github.com/cyr-ius/security-review/commit/76f9ecc412ac7ec9d2bf7dabcdcb7c78a320a597))
* add the per-project reports.write permission ([e2473c2](https://github.com/cyr-ius/security-review/commit/e2473c271c2f6a26350d483a02f073a7c0ba41c1))
* give each user roles and projects, the per-project permissions of its roles on its projects ([e1f316f](https://github.com/cyr-ius/security-review/commit/e1f316f73431212e7f07e86c2b86523d2f0843cd))
* give roles to the users on every project or on projects, without groups ([3395bc8](https://github.com/cyr-ius/security-review/commit/3395bc89bf68c62dcf8ae99fd76ee0034913fb9c))
* keep the roles for the site permissions and give per-project permissions on each project ([7bad8fd](https://github.com/cyr-ius/security-review/commit/7bad8fdc4dd55e04334b49e8ae38a063f8203a4e))
* suspend the OAuth grants when the login is turned off, and revoke them all on demand ([68a0d4a](https://github.com/cyr-ius/security-review/commit/68a0d4a01b7ce872d76e2ac23d95e2ebcc133134))
* suspend the OAuth login instead of refusing to start without the MCP endpoint URL ([04652a4](https://github.com/cyr-ius/security-review/commit/04652a42c7c83e79f40a404ef9ce0a6d1011d64d))
* **ui:** choose the allowed projects of a token in a drop-down list ([eda687f](https://github.com/cyr-ius/security-review/commit/eda687f7011d666cd70a59e66c033f7d9340965f))
* **ui:** choose the roles and the projects of a user in drop-down lists ([a920b92](https://github.com/cyr-ius/security-review/commit/a920b926aedafa8389bfa224520826ae5c20ba85))
* **ui:** edit the roles of the users on every project and on projects, and the OIDC mappings ([2ced2eb](https://github.com/cyr-ius/security-review/commit/2ced2eb9ee88e615dfbaed6a49a3d7e845811f25))
* **ui:** show the members of a project and their permissions in a modal from its row ([a8f4e49](https://github.com/cyr-ius/security-review/commit/a8f4e49171db0f3c6654fd53b9ce1d8bc6facb26))
* **ui:** warn about the permissions of a role that do not apply on a project ([7ddd8c5](https://github.com/cyr-ius/security-review/commit/7ddd8c542e115c28eed0b6043f0f9426355458c0))


### Bug Fixes

* **ui:** keep the menu of the multiple choice above its scrolling container ([9d1acc2](https://github.com/cyr-ius/security-review/commit/9d1acc259f36e4e55a11400016a7e2b4fa0e398b))


### Documentation

* describe the roles of the users on every project or per project and the OIDC mappings ([9e30c01](https://github.com/cyr-ius/security-review/commit/9e30c013c15ab4b66887afb003706c01d7fd65c9))
* Update index.fr.md ([ea8c4f4](https://github.com/cyr-ius/security-review/commit/ea8c4f4a2cc43c3fb842c8a8e894b9520ac179ab))
* Update index.fr.md ([84a6afb](https://github.com/cyr-ius/security-review/commit/84a6afbd8629d7995d27fa433125206ff059efc3))

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
