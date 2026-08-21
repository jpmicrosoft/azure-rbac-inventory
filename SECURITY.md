# Security

This document describes the security model of `azure-rbac-inventory`, its
supported versions, operational boundaries, and vulnerability-reporting
process.

- [Supported versions](#supported-versions)
- [Security model](#security-model)
- [Trust boundaries](#trust-boundaries)
- [Controls](#controls)
- [Known operational risks](#known-operational-risks)
- [Out of scope](#out-of-scope)
- [Secure usage guidance](#secure-usage-guidance)
- [Reporting a vulnerability](#reporting-a-vulnerability)

## Supported versions

| Version | Status |
|---|---|
| `0.10.x` (current release line) | Supported. Security fixes land here. |
| Current `main` | Supported. This is where fixes are developed. |
| `0.9.x` and older | Not supported. |

Reproduce against the latest release or current `main` when possible. Upgrade
to the newest release before reporting an issue that may already be fixed.

## Security model

Azure RBAC Inventory is a read-only inspection tool. It authenticates through
the Azure Identity SDK, queries Azure Resource Manager and Microsoft Graph, and
renders the returned identity and authorization data. It does not create,
modify, or delete Azure resources, role assignments, directory objects, or
entitlement-management objects.

The tool is designed to:

- send tokens only to the endpoints defined for the selected Azure cloud;
- limit collection to the requested identities and accessible authorization
  data;
- reject cross-origin Microsoft Graph pagination links;
- preserve errors and warnings when a complete inventory cannot be produced;
- protect terminal and HTML rendering from control-character and markup
  injection; and
- avoid writing credentials into reports.

These controls do not make generated reports public-safe. Reports can contain
object IDs, application IDs, role assignments, group memberships, resource
names, and scope paths. Treat every report as sensitive authorization data.

## Trust boundaries

The following inputs are untrusted and must remain data rather than authority:

- command-line values, search patterns, and imported identity files;
- display names, resource names, errors, and pagination links returned by Azure
  Resource Manager or Microsoft Graph; and
- report files consumed by downstream tools.

The selected cloud profile is a security boundary. Authentication audiences,
Azure Resource Manager endpoints, Microsoft Graph endpoints, and login
authorities must stay aligned for `AzureCloud`, `AzureUSGovernment`, or
`AzureChinaCloud`. A response from one service must not redirect an
authenticated request to another origin.

The local execution environment is also a trust boundary. Anyone who can
replace the binary, read the user's token cache, inspect process memory, or
access generated reports may gain sensitive information outside the controls
provided by this project.

## Controls

Current controls include:

- read-only requests to Azure Resource Manager and Microsoft Graph;
- cloud-specific authentication scopes and service endpoints;
- same-origin validation for Microsoft Graph pagination;
- assignment-scoped management-group name resolution rather than tenant-wide
  hierarchy export;
- non-fatal warnings and ID fallback when management-group names cannot be
  resolved;
- contextual HTML escaping and visible rendering of terminal control and
  bidirectional formatting characters;
- global timeouts and bounded concurrency for collection work;
- ignored `.env` files, token caches, binaries, and common report exports; and
- mocked API tests for security-sensitive request and output behavior.

Authentication may create a local token cache through the Azure Identity SDK.
The project does not write token values into its configuration or report
formats. Protect the host account and its local credential storage.

## Known operational risks

| Risk | Mitigation |
|---|---|
| Reports expose sensitive identity and authorization metadata | Store reports in access-controlled locations, minimize retention, and redact data before sharing. |
| Broad caller permissions reveal more tenant data | Use a dedicated identity with the least permissions required for the inventory. |
| Limited permissions or inaccessible subscriptions produce an incomplete view | Review every warning and error; do not treat partial output as proof that access does not exist. |
| Azure and Microsoft Graph data can be eventually consistent | Re-run checks after recent role, group, or directory changes. |
| CSV, JSON, Markdown, and XLSX may be rendered by downstream applications with their own security behavior | Open exports only in trusted, patched applications and treat all cell and field content as untrusted data. |
| Local authentication caches can contain reusable credentials | Protect the workstation profile and remove local caches according to your organization's credential-handling policy. |
| `--legacy-output` skips management-group display-name lookups | Use the default output for the most complete human-readable report; use legacy mode only for compatibility. |
| A modified or unofficial binary can bypass project controls | Prefer official release assets and verify them with the published `SHA256SUMS.txt`. |

## Out of scope

This project does not:

- secure or configure the Azure tenant, subscriptions, management groups, or
  Microsoft Graph permissions;
- determine whether an assignment is appropriate for an organization's policy;
- guarantee completeness when the caller lacks access to part of the tenant;
- control retention or access after a report is written or shared;
- protect a compromised workstation or execution environment;
- validate the behavior of spreadsheet, browser, terminal, or automation tools
  used to consume exports; or
- provide security support for unofficial builds or modified forks.

## Secure usage guidance

- Use the least-privileged identity that can perform the required inventory.
- Select the correct `--cloud` explicitly in sovereign-cloud automation.
- Review warnings before relying on a report.
- Keep report exports out of source control, chat, public issues, and build
  logs.
- Redact tenant IDs, subscription IDs, object IDs, resource names, and
  credentials from reproductions.
- Download releases from this repository and verify archive checksums before
  use in sensitive environments.
- Run live tests only against a dedicated nonproduction tenant and synthetic
  identities.

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability.

This repository does not currently expose GitHub's private vulnerability
reporting form. Contact the repository owner, `jpmicrosoft`, through a private
channel you already trust. Do not guess an email address or disclose the issue
through a public or unauthenticated channel. If GitHub's **Report a
vulnerability** option becomes available on the repository's **Security** page,
use that private form.

Include:

- output from `azure-rbac-inventory --version` and the relevant commit, if
  known;
- operating system and architecture;
- the exact command with credentials and real Azure identifiers redacted;
- a minimal reproduction using synthetic identifiers where possible;
- observed behavior, expected behavior, and any warnings or errors; and
- an impact assessment, especially whether a token, credential, or unrelated
  tenant data could be exposed.

There is no published response-time commitment. Do not disclose the issue
publicly until a coordinated disclosure timeline has been agreed with the
maintainer.
