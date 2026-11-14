# GitHub automation

Everything in this directory is pipeline configuration for RustSploit.

## Layout

```
.github/
├── workflows/
│   ├── ci.yml            per-PR gate: fmt, clippy, build, test, catalog, audit, docs
│   ├── security.yml      cargo-audit, cargo-deny, gitleaks, CodeQL, SBOM, dep review
│   ├── bug-hunt.yml      ASan + Miri + a logic/memory review worker
│   ├── code-quality.yml  in-place code-quality worker (audit or fix mode)
│   ├── release.yml       tag-triggered release: notes, matrix build, checksums, publish
│   ├── release-notes.yml PR preview of the next release notes; refreshes changelog-latest
│   └── nightly.yml       scheduled deep pass: advisory drift, baseline drift, all-features tests
├── bad-patterns.baseline       per-pattern counts (whole tree)
├── bad-patterns.files.baseline per-file per-section counts
├── deadcode.baseline           known-unwired / unused items
└── dependabot.yml
```

## The audit scripts

| Script | What it does |
| --- | --- |
| `scripts/audit-bad-patterns.sh` | The banned-pattern matrix from `docs/BAD_PATTERNS.md`. Modes: `--baseline` (gate on regressions), `--file-baseline` (per-file gate), `--changed-from <ref>` (focus on a diff), `--report <f>` (per-hit file:line report), `--drift-report <f>` (which patterns went up or down). |
| `scripts/audit-deadcode.sh` | Finds code that exists but is unreachable: files never compiled, missing `mod` targets, modules that never register, compiler-reported dead code, unused dependencies. |
| `scripts/annotate-findings.sh` | Turns a findings report into inline GitHub annotations plus a "BROKEN" summary. Section A (panics), B (swallowed errors) and C (lint suppression) become **error** annotations; everything else is a warning. |
| `scripts/check-docs.sh` | Link, staleness and coverage gate for the wiki. |
| `scripts/generate-release-notes.sh` | Renders release notes from the commit log plus `changelogs/fragments/*.md`. |
| `scripts/gen-module-catalog.py` | Fallback catalog generator for machines that cannot link the binary. CI cross-checks it against the real generator. |

The findings report is what makes the gates actionable: `audit-bad-patterns.sh
--report` writes `section<TAB>file<TAB>line<TAB>pattern<TAB>source`, and
`annotate-findings.sh` turns each row into an annotation on the pull-request
diff.

## Design rules

**Every action is pinned to a commit SHA.** A tag can be moved; a commit
cannot. The version is kept in a trailing comment so dependabot can update
both.

**Workers are independent.** Each job owns one concern and reports on its own,
so one slow or failing worker never hides the state of the others. The `gate`
job in `ci.yml` aggregates them into the single required status check.

**Gates are baselined, not absolute.** The repository carries real legacy
debt. An absolute gate is red on day one and therefore ignored. Each gate
records the current state and fails only when that state gets *worse*. Baselines
are expected to shrink; never add to one to make a gate pass.

**Heavy jobs use a larger runner.** The crate has ~690 modules and links a
vendored OpenSSL, so a debug build with debuginfo OOMs a 7 GB machine. CI sets
`CARGO_PROFILE_DEV_DEBUG=0` and `RUSTFLAGS="-C debuginfo=0"`, and runs the
compile/test jobs on `ubuntu-latest-8-cores`. Override with the `RUNNER_HEAVY`
repository variable if the account has no larger runners.

## Repository variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `RUNNER_HEAVY` | `ubuntu-latest-8-cores` | Runner label for the compile/test jobs. Set to `ubuntu-latest` on a plan without larger runners. |

## Repository secrets

| Secret | Used by | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | all | Built-in. Write access is granted per-job, not workflow-wide. |
| `CLAUDE_CODE_OAUTH_TOKEN` | `code-quality.yml`, `bug-hunt.yml` | The review worker. |
| `ANTHROPIC_API_KEY` | `code-quality.yml`, `bug-hunt.yml` | Alternative to the OAuth token. |

The review workers degrade to "not run" when no credential is configured, so
the rest of the pipeline still works.

## The review workers

`code-quality.yml` and `bug-hunt.yml` use the Claude Code action. Both are
**anchored to the repository's own rules** rather than free-form opinion:

- `code-quality.yml` runs `scripts/audit-bad-patterns.sh` and
  `scripts/check-docs.sh` first, and the worker reports what those scripts
  found plus anything else it finds in the diff.
- `bug-hunt.yml` builds an inventory of every `unsafe` block, raw-pointer
  operation, unchecked index and narrowing cast in `src/`, and the worker
  checks whether the diff introduces or worsens any of them.

`bug-hunt.yml` also runs the test suite under AddressSanitizer and the
pure-logic tests under Miri. Those are the workers that find memory bugs for
real — a review finds the ones you can read, a sanitizer finds the ones you
cannot.
