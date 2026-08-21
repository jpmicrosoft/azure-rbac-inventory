# Contributing

Thanks for improving `azure-rbac-inventory`. This tool handles Azure
credentials and produces reports containing sensitive identity and
authorization data, so security and output compatibility are part of every
change.

- [Prerequisites](#prerequisites)
- [Get the code running](#get-the-code-running)
- [Required checks](#required-checks)
- [Platform note: the race detector](#platform-note-the-race-detector)
- [Keep behavior and documentation in sync](#keep-behavior-and-documentation-in-sync)
- [Security-sensitive review checklist](#security-sensitive-review-checklist)
- [Commit and pull request workflow](#commit-and-pull-request-workflow)
- [Release workflow](#release-workflow)
- [Code style](#code-style)

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | 1.26 or later | [`go.mod`](go.mod) declares `go 1.26.0`. |
| Git | Any recent version | Used to clone the repository and submit changes. |
| golangci-lint | 2.11.3 | CI pins this version in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). |
| Azure access | Not required for unit tests | CI runs the test suite without Azure credentials. Use only a dedicated nonproduction tenant for optional live validation. |

## Get the code running

```powershell
git clone https://github.com/jpmicrosoft/azure-rbac-inventory.git
cd azure-rbac-inventory
go build .
go run . --help
```

Do not commit built binaries, token caches, `.env` files, or generated reports.
The repository's [`.gitignore`](.gitignore) excludes the common forms of these
artifacts.

## Required checks

Run these checks before opening a pull request. They cover the CI gates in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) plus `gofmt`, which is
not enforced by CI but is expected for all contributions:

```powershell
gofmt -l .                        # not a CI gate, but must print nothing
go vet ./...
go test ./... -count=1
go test -race ./... -count=1
go build ./...
golangci-lint run ./...
```

`gofmt -l .` must print nothing. The linter must report no issues. Use
`-count=1` to disable cached test results.

Scope tests while iterating, then run the complete gate before submitting:

```powershell
go test ./internal/output ./internal/report -count=1
go test ./internal/rbac -run TestName -count=1
```

Replace `TestName` with the specific test you are running.

## Platform note: the race detector

The Go race detector is unavailable on `windows/arm64`. Developers on that
platform should run every other local check and rely on CI's supported runners
for the race gate. Do not weaken or skip the CI race test.

## Keep behavior and documentation in sync

User-visible behavior is a contract. Update all affected surfaces in the same
pull request.

| If you change... | Also update... |
|---|---|
| A command, flag, default, or help string | [`README.md`](README.md), command tests, and examples that show the old behavior |
| A report field or output schema | Every affected formatter, modern and `--legacy-output` tests, and compatibility documentation |
| Azure cloud endpoints or authentication | Cloud and authentication tests, [`README.md`](README.md), and [`SECURITY.md`](SECURITY.md) |
| RBAC or Microsoft Graph collection behavior | Mocked API tests, warning/error behavior, and permission documentation |
| A security boundary or sensitive-data behavior | Security regression tests, [`SECURITY.md`](SECURITY.md), and [`CHANGELOG.md`](CHANGELOG.md) |
| Anything user-visible | [`CHANGELOG.md`](CHANGELOG.md) |

Examples and tests must use synthetic identifiers and resource names. Never
commit real tenant IDs, subscription IDs, object IDs, resource names, report
exports, credentials, or tokens.

## Security-sensitive review checklist

Apply this checklist to authentication, HTTP clients, cloud endpoints, identity
resolution, RBAC collection, file input, and output formatting:

- [ ] Does the change preserve read-only Azure ARM and Microsoft Graph behavior?
- [ ] Can any token, credential, authorization header, or cache content reach
      logs, errors, reports, or tests?
- [ ] Are caller-controlled paths, identifiers, patterns, and URLs validated
      before use?
- [ ] Do pagination and follow-up requests remain pinned to the selected
      cloud's expected service origin?
- [ ] Could the change collect or expose tenant data unrelated to the requested
      identities or assignments?
- [ ] Is API-provided text escaped or sanitized for its output context?
- [ ] Do partial permission failures produce clear warnings instead of silent,
      success-shaped output?
- [ ] Are cancellation, timeouts, and concurrency limits preserved?
- [ ] Are CSV, HTML, JSON, Markdown, table, and XLSX outputs consistent where
      the feature applies?
- [ ] Does `--legacy-output` still preserve its documented compatibility
      contract?
- [ ] Are security-relevant edge cases covered with mocked, offline regression
      tests?

Changes that broaden data collection, add a network destination, alter cloud
selection, expose additional report fields, or weaken an existing validation
need explicit justification in the pull request and an update to
[`SECURITY.md`](SECURITY.md).

## Commit and pull request workflow

1. Branch from `main`.
2. Make focused commits with concise imperative subjects.
3. Run the [required checks](#required-checks).
4. Update tests, documentation, and the changelog with the behavior change.
5. Open a pull request against `main` that explains what changed, why, the
   security impact (even if none), and how it was verified.
6. Address review feedback with follow-up commits and keep CI green.

Do not rewrite published history or force-push over a branch that others are
reviewing. Never include credentials, real Azure identifiers, sensitive report
data, generated binaries, or token caches in a commit, issue, or pull request.

## Release workflow

Releases are maintainer-owned and tag-driven through
[`.github/workflows/release.yml`](.github/workflows/release.yml). Contributors
should not create or move release tags.

The maintainer:

1. lands the release changes on `main` with CI green;
2. updates [`CHANGELOG.md`](CHANGELOG.md) with the version and release date;
3. creates a lightweight `vX.Y.Z` tag on the release commit; and
4. pushes the tag, which reruns tests and lint, builds six platform archives,
   generates `SHA256SUMS.txt`, and publishes the GitHub release.

Update the supported release line in [`SECURITY.md`](SECURITY.md) as part of
each versioned release.

## Code style

- `gofmt` determines Go formatting.
- Keep packages focused and package names lowercase.
- Add doc comments to exported identifiers.
- Comments should explain why, especially around security and compatibility.
- Wrap errors with actionable context; do not silently suppress failures.
- Prefer table-driven tests and add regression cases for fixed defects.
- Follow existing repository patterns before introducing a new abstraction.
