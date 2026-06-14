# Contributing

This document is for everyone working on `libtunnel` — humans and AI agents alike.
It covers the layout, the local dev loop, the conventions that bite, and how a
change gets from an issue to a release.

## Where to find things

Deep-link by filename; line numbers will drift.

| Topic                                          | Source                                                           |
| ---------------------------------------------- | ---------------------------------------------------------------- |
| Façade (`New`, backends, providers, handoff)   | [`lib.go`](./lib.go)                                             |
| Stable contract (`Tunnel`, `Connected`, `Provider[T]`, `Backend[T]`, `Spec`) | [`v1/v1.go`](./v1/v1.go) |
| Cloudflare `Spec` type                         | [`v1alpha1/cloudflare/spec.go`](./v1alpha1/cloudflare/spec.go)   |
| Core struct + `New` constructor + `Engine` contract | [`v1alpha1/v1alpha1.go`](./v1alpha1/v1alpha1.go)            |
| Lazy getters + `With*` mutators + DNS readiness | [`v1alpha1/tunnel.go`](./v1alpha1/tunnel.go)                     |
| Generic providers (`Static`, `Env`) + handoff helpers | [`v1alpha1/provider.go`](./v1alpha1/provider.go)          |
| Cloudflare engine (cloudflared supervisor wiring) | [`v1alpha1/cloudflare/cloudflare.go`](./v1alpha1/cloudflare/cloudflare.go) |
| Quick-tunnel provider (api.trycloudflare.com)  | [`v1alpha1/cloudflare/quicktunnel.go`](./v1alpha1/cloudflare/quicktunnel.go) |
| Unit tests + fuzz target                       | [`v1alpha1/tunnel_test.go`](./v1alpha1/tunnel_test.go)           |
| Live e2e scenarios + helpers                   | [`e2e/live_test.go`](./e2e/live_test.go), [`e2e/util_test.go`](./e2e/util_test.go) |
| Subprocess handoff unit tests                  | [`lib_test.go`](./lib_test.go)                                   |
| godoc examples                                 | [`v1/example_test.go`](./v1/example_test.go)                     |
| e2e harness + runner                           | [`e2e/e2e_test.go`](./e2e/e2e_test.go)                           |
| Worked examples                                | [`examples/`](./examples)                                        |
| Build / lint / test commands                   | [`Makefile`](./Makefile)                                         |
| Release + skip release regex                   | [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)         |
| CodeQL scan                                    | [`.github/workflows/codeql.yml`](./.github/workflows/codeql.yml) |
| OpenSSF Scorecard scan                         | [`.github/workflows/scorecard.yml`](./.github/workflows/scorecard.yml) |
| Dependabot config                              | [`.github/dependabot.yml`](./.github/dependabot.yml)             |
| Cosign verification recipe                     | [`SECURITY.md`](./SECURITY.md)                                   |
| Orientation for AI agents                      | [`CLAUDE.md`](./CLAUDE.md)                                       |

## Module layout

Stable/alpha versioning, with backend engines in alpha subpackages:

```
github.com/cnuss/libtunnel                      — root façade: New, backends,
                                                  providers, handoff helpers.
github.com/cnuss/libtunnel/v1                   — stable Tunnel/Connected +
                                                  Provider[T]/Backend[T] contract.
github.com/cnuss/libtunnel/v1alpha1             — lazy tunnel core + generic
                                                  providers. May change between
                                                  alpha revisions.
github.com/cnuss/libtunnel/v1alpha1/cloudflare  — the cloudflared quick-tunnel
                                                  engine + its Spec type.
```

Application code imports the root (`libtunnel.New(...)`). Code that needs to
declare types against the interfaces imports `v1`. Direct access to the
`TunnelImpl[T]` struct and the `Engine` contract lives in `v1alpha1`.

## Local development

Requires Go 1.26 or later (cloudflared's floor).

```sh
git clone https://github.com/cnuss/libtunnel.git
cd libtunnel
make test   # library unit + fuzz tests (fast, in-package)
make e2e    # live tier: real tunnels; skipped unless LIBTUNNEL_E2E_LIVE=1
```

Run a specific example locally:

```sh
make run serve
make run subprocess
```

## Test layout

Three tiers, each with a distinct job — don't blur them:

- **`*_test.go` next to the code** — unit tests: anything with fabricated
  specs or fakes, however elaborate. Includes fuzz targets, the godoc
  examples in `v1/example_test.go`, and the subprocess handoff scenarios at
  the repo root (`lib_test.go` — re-exec'd children adopting fabricated
  specs, no network).
- **`examples/`** — real-world, simple-ish API usage written for humans. An
  example demonstrates; it never asserts. Assertion logic belongs in `e2e/`.
- **`e2e/`** — **live tunnels only**, gated behind `LIBTUNNEL_E2E_LIVE=1`
  and not meant for human consumption. The harness builds and runs the
  example binaries against the real edge and asserts on their output, plus
  live scenario tests (shared-tunnel subtests, TLS origin, resurrection,
  concurrent tunnels). If a check can pass without a real tunnel, it is a
  unit test, not e2e.

## Before you push

- `gofmt -w .`
- `go vet ./...`
- `make test`
- `make e2e`

CI runs the same on every PR.

## Conventions that bite

Easy to get wrong from the diff alone:

- **`examples/` is intentionally duplicated.** Each `main.go` is a
  copy-pasteable starter; no shared internal package. Don't refactor it into
  one.
- **godoc example funcs can't bind to generic types.** `go vet` rejects
  `ExampleTunnel_*` in `v1` because `Tunnel` is parameterized — its example
  checker hasn't caught up with generics. Work around it with package-level
  example names (`Example_handoff` etc.). See [`v1/example_test.go`](./v1/example_test.go).
- **e2e builds binaries at runtime**, so the test cache can't see example
  source changes — `make e2e` passes `-count=1` to force a rebuild.
- **Live examples are gated.** `serve` and `subprocess` mint real tunnels from
  `api.trycloudflare.com`, which rate-limits — minting from all 12 CI matrix
  cells would trip 429s, so one stable-Go cell per OS (ubuntu-24.04,
  windows-2025, macos-26) sets `LIBTUNNEL_E2E_LIVE=1` and the rest skip the
  live tier. For local verification, prefer `make run serve` (one tunnel)
  over the full live suite. A `served: error code: 1033`
  from a fresh tunnel is edge route propagation lag (more likely with
  several tunnels minted at once) — rerun before suspecting the code.
- **cloudflared registers prometheus collectors globally.** The Cloudflare
  engine swaps `prometheus.DefaultRegisterer` to a noop (under a mutex) for
  the construction window so host applications' metrics stay clean. Don't
  "simplify" that away.
- **Skip-release token must be line-anchored.** The regex in
  [`ci.yml`](./.github/workflows/ci.yml) (`resolve tag` step) is
  `^[[:space:]]*\[skip release\][[:space:]]*$`. Inline prose mentions are safe;
  a standalone line in the commit body opts out.
- **Cosign / Scorecard tags are annotated.** `ossf/scorecard-action` publishes
  annotated tags; pinning the tag-object SHA fails Sigstore verification
  ("imposter commit"). Pin to the commit underneath (see existing entries in
  [`scorecard.yml`](./.github/workflows/scorecard.yml)).

## Adding an example

Examples live in `./examples/<name>/main.go`. Keep each example self-contained
(there's no shared internal package — the duplication is intentional, so each
example is copy-pasteable on its own).

Print a single recognizable line so the e2e harness can assert on it, then add
a row to the `cases` table in `e2e/e2e_test.go` (name + expected substring) and
to the README's example table. Mark the case `live: true` if it mints a real
tunnel — those only run under `LIBTUNNEL_E2E_LIVE=1`.

## Branch / PR flow

**Every change starts with an issue** — no exceptions, including retroactive
cleanups. The PR body always carries a `Closes #<n>` line so the merge
auto-closes the tracking issue and leaves a paper trail.

```sh
gh issue create --title "…" --body "…"                    # 1. issue first
git switch -c <type>/<topic>                              # 2. branch
# ... edits, commit ...
git push -u origin <type>/<topic>
gh pr create --title "<type>: …" --body "Closes #<n>. …"  # 3. PR refs the issue
# CI green ⇒
gh pr merge <pr#> --squash --delete-branch
```

`main` is protected (`ci` required; no force-push). Don't push directly to it
for routine work — PR flow gives CI + auto-release a clean audit trail. Pushing
to `main` auto-bumps a patch tag and signs the release (see Releasing below).

Don't commit secrets. [`.gitignore`](./.gitignore) covers `.env*`, `.claude/`,
etc.

## Pull requests

- Keep PRs focused. One feature or fix per PR.
- Include test coverage for behavior changes — lib tests (`v1alpha1/`) for API
  changes, e2e tests (`e2e/e2e_test.go`) for example-visible changes.
- **Keep the README in sync with the façade.** The README mirrors the public
  surface, so any change to it must update the README in the same PR:
  - a new/changed/removed method on the `v1` interfaces or the façade → update
    the **API at a glance** block and the **Quick Start** snippet;
  - a new example → add a row to the **Examples** table;
  - a renamed package/version tier → update the **Layout** tree.
  Treat the README's code blocks as documentation that must compile against the
  current API — stale snippets are a review blocker.
- Signed commits preferred. The repo enables commit signing locally; CI does
  not enforce signatures.

## Commit messages

Short subject (≤ 72 chars), imperative mood ("Add X", not "Added X").
Wrap body at ~72 cols. Explain the *why*; the diff covers the *what*.

## Releasing

Patch releases are automatic. Every push to `main` runs the `Release`
workflow, which bumps the patch component of the latest `v*` tag,
re-runs `go vet`, `go build`, `make test`, and `make e2e` against that
ref, then:

- pushes the new tag,
- creates a GitHub Release with auto-generated notes, and
- warms `proxy.golang.org` so [pkg.go.dev](https://pkg.go.dev/github.com/cnuss/libtunnel)
  surfaces the new version without manual prodding.

To opt a commit out of the auto-bump, put `[skip release]` on its own
line in the commit body. (It must be the only thing on its line, so
prose mentioning the token inline doesn't accidentally suppress.)

For a minor or major bump, tag locally and push the tag — the workflow
treats a manual tag as the version of record and skips the bump:

```sh
git tag v0.2.0
git push --tags
```

Tags must follow `vMAJOR.MINOR.PATCH` (Go module semver).

## License

By contributing you agree your contributions are licensed under the
[MIT License](./LICENSE).
