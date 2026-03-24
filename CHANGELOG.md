# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-03-24

### Added
- **Two-pass RBAC diff with inferred matches** — when workload-normalized scope matching (pass 1) cannot resolve a scope, a RoleName+ScopeType fallback (pass 2) catches structural matches and displays them as "Inferred" with amber `≈` markers
- New `Inferred` field in `RBACDiff` (JSON: `"inferred"`) for downstream consumption
- Inferred matches section in both table CLI and HTML output with explanatory text

## [0.7.1] - 2026-03-24

### Fixed
- **Target summary click navigation** — clicking a target name in the model compare summary now auto-opens the collapsed details section, smooth-scrolls to it, and highlights it with a brief outline for easy identification

## [0.7.0] - 2026-03-23

### Added
- **Smart environment-aware workload matching** — scope normalization now replaces environment segments (prod, dev, stg, mod, uat, qa, etc.), topology tiers (hub, spoke), and numeric suffixes so that identities in different environments match on workload name
- New `--env-segments` flag for user-defined extra segments to normalize (e.g. `--env-segments "pool,core,shared"`)
- Position-independent matching works regardless of naming convention order

## [0.6.0] - 2026-03-23

### Added
- **Model RBAC reference section** — model compare output (table and HTML) now shows the model identity's full RBAC assignments as a collapsible reference before the target comparison
- **Full scope path in drift items** — Missing and Extra RBAC items display the full ARM resource ID (scope path) alongside RoleName and ScopeType for unambiguous identification across subscriptions and resource groups
- Compact shared-item labels omit the scope path for cleaner display

## [0.5.0] - 2026-03-23

### Added
- Search bar in HTML model compare report to filter target summary table
- Clickable target names in HTML summary linking to drift detail sections
- **Model RBAC reference section** — model compare output (table and HTML) now shows the model identity's RBAC assignments as a reference before the target comparison
- **Full scope path in drift items** — Missing and Extra RBAC items in both 1:1 and model compare now display the full ARM resource ID (scope path) alongside RoleName and ScopeType for unambiguous identification
- Compact shared-item labels (`rbacLabelShort`) omit the scope path since shared items already match

### Fixed
- **Structural RBAC matching in model compare** — same role at the same scope level (e.g. Reader at any Subscription) is now treated as a match regardless of exact scope path, preventing false "Missing + Extra" pairs
- Application registrations blocked from model compare (model = hard error, targets = skip with warning) since apps don't have RBAC assignments

## [0.4.0] - 2026-03-23

### Added
- **Workload-aware model comparison** — `compare --model <id> --workload-key <name>` for intelligent RBAC pattern matching across workload-specific identities
- Auto-detection of workload name from RBAC scope paths when `--workload-key` is omitted
- Scope normalization — replaces workload-specific segments with `{workload}` placeholder for structural comparison
- Noise segment filtering to improve workload name detection accuracy

### Security
- Input length validation extended to `--workload-key` flag (256-character max)

## [0.3.0] - 2026-03-23

### Added
- **Compare subcommand** — `azure-rbac-inventory compare <id-A> <id-B>` for 1:1 identity RBAC comparison
- **Model compare mode** — `compare --model <model-id> <targets...>` for 1:N comparison with match percentage scoring
- Compare diffs across RBAC role assignments, directory roles, group memberships, and access packages
- HTML and JSON export for comparison results (`--export diff.html`)
- Table and JSON stdout output formats for comparisons

### Security
- Scope-aware RBAC diff — comparison keys use full scope path, not just scope type
- Export path validation — rejects symlinks and verifies parent directory before writing
- Input length validation — 256-character max on `--model` flag and positional args
- Memory-bounded model compare — maxTargets capped at 200
- Explicit error for unsupported output formats (csv/markdown) instead of silent fallthrough

## [0.2.0] - 2026-03-20

### Added
- CI/CD authentication support: `--auth environment` (service principal via env vars), `--auth managed-identity` (Azure Managed Identity), `--auth azurecli` (Azure CLI credential)
- Pre-authentication validation for `azurecli` with actionable error hints for scope and permission issues
- CI/CD pipeline examples in README (GitHub Actions, Azure DevOps)
- Troubleshooting guide for Azure CLI auth, SPN permissions, and token cache issues

### Changed
- Release workflow now gates on CI (test + lint must pass before building artifacts)
- `PreAuthenticate()` skipped for `environment` and `managed-identity` methods (stateless, no browser prompts)

## [0.1.0] - 2026-03-20

### Added
- Identity resolution by object ID, app ID, or display name pattern
- Azure RBAC role assignment queries across all accessible subscriptions
- Entra ID directory role assignment queries
- Access package assignment and request queries (opt-in via `--include-access-packages`)
- Group membership listing (direct and transitive)
- Inherited RBAC through group memberships (opt-in via `--include-group-rbac`)
- Pattern search with wildcard support (`*` prefix, suffix, contains)
- File input for batch identity checks (text, CSV, JSON formats)
- Export to CSV, HTML, Markdown, XLSX, and JSON
- Grouped RBAC output by resource type
- Azure Commercial and Azure Government cloud support
- Interactive browser and device-code authentication
- Pre-authentication to prevent double browser prompts
- Global execution timeout (`--timeout`, default 30m)
- Per-identity export mode (`--per-identity`)

### Security
- OData filter injection prevention (`escapeOData`, `escapeODataValue`)
- `$search` injection prevention (`escapeODataSearch`)
- ARM filter escaping (`escapeARMFilter`)
- CSV formula injection sanitization (`sanitizeCSVCell`)
- Markdown content injection prevention (full metacharacter escaping)
- NextLink origin validation (prevents token theft via redirect)
- Input file size limit (10 MB) and entry count limit (10,000)
- Resolved identity count cap (1,000)
- Response body size limit (10 MB) and pagination page limit (100)
- UUID validation on all identity, tenant, and subscription IDs
- Concurrency cap (1–50) for group RBAC fan-out
- File export permissions set to `0600`
