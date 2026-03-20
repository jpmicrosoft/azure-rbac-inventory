# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-03-20

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
