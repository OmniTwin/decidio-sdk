# decidio

The short name for the Decidio SDK's command line.

```bash
npx decidio                      # asks one question, then does the thing you picked
npx decidio quickstart --demo    # the two-minute tour on this machine, no account
```

`npx decidio …` runs exactly the same CLI as `npx @decidio/sdk …` — this package holds nothing but the hand-off to
[`@decidio/sdk`](https://www.npmjs.com/package/@decidio/sdk), pinned to the same version and released with it. Read
that package's README for everything the command line does; the SDK itself (`import { guard } from "@decidio/sdk"`)
lives there too — this package is not something to import.

Upgrade the way you installed: `npx decidio@latest` clears an old npx cache; `npm i -g decidio@latest` for a global
install.

Built by OmniTwin Technologies Inc. — [decidioai.com](https://decidioai.com/#early-access).
