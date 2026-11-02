## What does this PR change?

<!-- One or two sentences: what and why. Tests must pass: `make` && `make test`. -->

## Contribution grant (required)

This project is dual-licensed under the **GNU Affero General Public License
v3.0** and a **commercial license** held by the author (Dipanjan Patra),
so that closed-source and hosted use remains available to licensees.

By opening this pull request you agree that your contribution is licensed
under **both**:

- the **GNU Affero GPL v3.0**, perpetually and irrevocably; and
- the **commercial license** the author grants, allowing incorporation into
  the commercial offering without further permission.

Details: [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md#licensing-of-your-contributions).

**I grant the above** — uncomment the line below before submitting:

<!-- I grant my contribution under both AGPL v3.0 and the commercial license. -->

## Self-check

- [ ] `make` builds clean, `make test` passes
- [ ] No dynamic allocation outside bounded startup; every wait has a deadline
- [ ] Every read is length-checked before use
- [ ] Security-sensitive changes discussed privately first — GitHub private vulnerability reporting (Security tab)
