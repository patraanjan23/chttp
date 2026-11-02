# Contributing to chttp

Thanks for your interest. Two paths, both welcome:

## Bug fixes and features (AGPL path)

Open a pull request against `main`. Keep changes consistent with the house
rules the code follows — no dynamic allocation outside bounded startup, every
wait has a deadline, every read is length-checked. The build and tests:

```sh
make            # build with Fil-C
make test       # run the test suite
make analyze    # clang static analyzer
```

## Licensing of your contributions

This project is dual-licensed under the GNU Affero GPL v3.0 and a commercial
license held by the author (Dipanjan Patra). To keep
the commercial path grantable, **by submitting a contribution you agree it is
licensed under both** — AGPL v3.0 perpetually and irrevocably, plus the right
for the author to incorporate it into the commercial offering. No separate
signing step for now; a CLA bot may enforce this formally later.

## Shell out of the AGPL? (commercial path)

If you want to build a closed-source product or hosted service on chttp and
not release your source, you need a commercial license from the copyright
holder: contact **[Dipanjan Patra](https://github.com/patraanjan23)** via a
GitHub issue or discussion on this repository, tagged `commercial`. Describe
your use case and scale, and terms will be quoted.

Anything else — questions, design objections, security reports — reaches the
author through the same channels. Please report vulnerabilities privately
using GitHub's private vulnerability reporting (Security → Report a
vulnerability) rather than opening a public issue.
