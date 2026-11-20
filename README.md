# Decidio SDK: release source

This repository builds and publishes the Decidio developer packages:

| Folder | Package |
|---|---|
| `sdk/` | [`@decidio/sdk`](https://www.npmjs.com/package/@decidio/sdk) on npm |
| `verify/` | [`@decidio/verify`](https://www.npmjs.com/package/@decidio/verify) on npm, the offline receipt verifier |
| `alias/` | [`decidio`](https://www.npmjs.com/package/decidio) on npm, the `npx decidio` short name |
| `python/` | [`decidio`](https://pypi.org/project/decidio/) on PyPI |

Every release is built here by `.github/workflows/publish.yml` and published with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements) and PyPI attestations. Each package's page on
npm and PyPI links back to the commit and workflow run that built it.

Before anything is published, `scripts/check-release.mjs` checks that every package contains exactly the files listed in
`release.json`, with the listed SHA-256 hashes.

## Checking a package you installed

```sh
npm audit signatures
```

This checks the registry signatures and provenance attestations of every package in your project, `@decidio/sdk` among
them.

## Contributing

This repository is a release mirror: each release is one commit, and pull requests are not merged here.

- Documentation: <https://decidioai.com/developers/>
- Questions and bug reports: support@decidioai.com
- Security issues: security@decidioai.com

## Licence

- `sdk/`, `alias/` and `python/` (`@decidio/sdk`, `decidio` on npm, `decidio` on PyPI): the Functional Source License,
  Version 1.1, ALv2 Future License (`LICENSE`). Any use is permitted except a competing product or service, and each
  version is also available under the Apache License, Version 2.0, from the second anniversary of its release.
- `verify/` (`@decidio/verify`): the Apache License, Version 2.0 (`verify/LICENSE`), so anyone can check a receipt.
- Versions 0.20.1 and earlier of every package were released under the Apache License, Version 2.0.
