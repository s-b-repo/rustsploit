# Copilot Instructions

This repository is versioned automatically by **Release Please**. Every commit on the default branch and every PR title must follow **Conventional Commits** so the release bot can produce a correct version bump and changelog.

## Format

```
<type>[optional scope][!]: <short description>

[optional body]

[optional footer, e.g. BREAKING CHANGE:]
```

## Types

| Type | Version bump | In CHANGELOG |
| --- | --- | --- |
| `feat` | minor | yes — Features |
| `fix` | patch | yes — Bug Fixes |
| `perf` | patch | yes — Performance |
| `revert` | patch | yes — Reverts |
| `docs` | — | no |
| `style` | — | no |
| `chore` | — | no |
| `refactor` | — | no |
| `test` | — | no |
| `build` | — | no |
| `ci` | — | no |

**Breaking changes bump the major version.** Signal them either with `!` after the type/scope (`feat!: rename public API`) or with a `BREAKING CHANGE:` footer.

## Rules for Copilot when drafting commits or PR titles

1. Pick the type by the actual effect of the change, not the author's intent.
2. Keep the description in imperative mood: "add X", not "added X" or "adds X".
3. Keep the subject under 72 characters.
4. Use a scope when the change is confined to one area: `feat(auth): ...`, `fix(parser): ...`.
5. For breaking changes, use `!` **and** describe the migration in the body.
6. Never combine an independent `feat` and `fix` into one commit — each deserves its own changelog entry.

## Examples

- `feat: add OIDC provider selection` — minor
- `fix(parser): handle empty input` — patch
- `feat!: rename public API` — major (with migration notes in the body)
- `chore: bump dev dependencies` — no release
- `docs: clarify README` — no release

## Release flow (do not fight the bot)

- On every push to `main`, the release workflow runs.
- When there are releasable commits since the last tag, Release Please opens a PR titled `chore(main): release <version>` that updates the manifest and `CHANGELOG.md`.
- **Do not edit that PR's branch by hand.** Review, then merge it. Merging creates the Git tag and GitHub Release.

## Files

- `release-please-config.json` — release types, packages, changelog sections
- `.release-please-manifest.json` — the version Release Please thinks is current
- `.github/workflows/release-please.yml` — calls `s-b-repo/release-automation`
- `.github/workflows/pr-title-lint.yml` — lints PR titles as Conventional Commits
