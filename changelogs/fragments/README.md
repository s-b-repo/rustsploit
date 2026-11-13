# Release-note fragments

A fragment is a short markdown file describing something the commit subject
cannot express: a migration step, a security advisory, a breaking change, or
a user-visible behaviour change.

Each file here is included verbatim under a **Notable changes** heading in the
generated release notes by `scripts/generate-release-notes.sh` — the same
script the release pipeline and the PR preview both use, so a preview and the
published notes cannot differ.

## How to use it

1. Create a file named after the topic, e.g. `pq-key-rotation.md`.
2. Write the note in markdown. Start with a `#` heading — the generator
   strips it so the fragment does not nest a heading inside a heading.
3. Open a pull request with the fragment. It is picked up automatically; there
   is no registry to update and no script to run.

## Naming

Use a kebab-case topic, not a version number — the same fragment may apply to
more than one release:

```
changelogs/fragments/pq-key-rotation.md
changelogs/fragments/api-auth-breaking-change.md
```

## Example

```markdown
# PQ host key rotation

The API server now accepts `pq_key_path` in the config file. Existing
installations keep working; the flag is only needed when the host key is
stored outside `~/.rustsploit/`.
```

Fragments are removed once they have shipped, so the directory only ever
contains notes for releases that have not happened yet.
