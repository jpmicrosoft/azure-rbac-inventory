# Azure RBAC Inventory

[![CI](https://github.com/jpmicrosoft/azure-rbac-inventory/actions/workflows/ci.yml/badge.svg)](https://github.com/jpmicrosoft/azure-rbac-inventory/actions/workflows/ci.yml)
[![Release](https://github.com/jpmicrosoft/azure-rbac-inventory/actions/workflows/release.yml/badge.svg)](https://github.com/jpmicrosoft/azure-rbac-inventory/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jpmicrosoft/azure-rbac-inventory)](https://goreportcard.com/report/github.com/jpmicrosoft/azure-rbac-inventory)

A single-binary CLI tool that reports **all RBAC assignments, Entra ID directory roles, access package assignments, and group memberships** for any Azure identity — and can **compare** assignments between identities to detect drift.

Supports **Azure Commercial** and **Azure Government** clouds.

## Features

- **Identity Resolution** — Accepts an object ID or app ID and automatically resolves the identity type (user, SPN, managed identity, app registration, group)
- **Azure RBAC** — Queries role assignments across all accessible subscriptions at every scope level (management group, subscription, resource group, resource)
- **Entra ID Directory Roles** — Reports directory role assignments (Global Admin, User Admin, etc.)
- **Access Packages** — Optionally queries Identity Governance entitlement management for all assignment states (Delivered, Delivering, Pending Approval, Expired, etc.) with `--include-access-packages`
- **Access Package Requests** — Shows pending, approved, and denied access package requests (with `--include-access-packages`)
- **Group Memberships** — Lists direct and transitive group memberships
- **Inherited RBAC** — Optionally queries RBAC assignments inherited through group memberships (`--include-group-rbac`). Note: group memberships are always listed in the report; this flag adds the additional RBAC lookups per group.
- **Compare** — Compare RBAC, directory roles, groups, and access packages between two identities (1:1) or one baseline vs. many targets (1:N model compare) with match% and drift detection
- **Pattern Search** — Search by display name, SPN name, or wildcard pattern instead of requiring an exact ID
- **File Input** — Batch-check multiple identities from a text file
- **Export Formats** — Export results to CSV, HTML, Markdown, XLSX, or JSON files
- **Grouped RBAC Output** — RBAC assignments are grouped by resource type for easier reading
- **Dual Cloud** — Works with both Azure Commercial and Azure Government

## Requirements

### Runtime
- Windows, macOS, or Linux (amd64 or arm64)
- Network access to Azure ARM and Microsoft Graph endpoints (see [Cloud Endpoints](#cloud-endpoints))
- An Azure account with appropriate permissions (see [Required Permissions](#required-permissions))

### Build from Source
- Go 1.26 or later
- Git (to clone the repository)
- Make (optional, for cross-platform builds)

### Azure Permissions

The identity running this tool needs these permissions at minimum:

| Permission | Scope | Purpose | Required? |
|---|---|---|---|
| `Reader` | Subscriptions or Management Groups | List and query RBAC role assignments | Yes |
| `Directory.Read.All` | Microsoft Graph (Application or Delegated) | Resolve identities, directory roles, group memberships | Yes |
| `EntitlementManagement.Read.All` | Microsoft Graph (Application or Delegated) | Access package assignments and requests | Optional — only needed with `--include-access-packages` |

> **Tip:** The tool uses interactive browser authentication by default. Graph permissions are granted as **delegated permissions** — consent to them when prompted during sign-in.

## Quick Start

```bash
# Download the binary for your platform from Releases (or build from source)

# Login to Azure
# The tool uses interactive browser login by default

# Check an identity
./azure-rbac-inventory check <object-id-or-app-id>

# Azure Government
./azure-rbac-inventory check <object-id> --cloud AzureUSGovernment

# Export to JSON
./azure-rbac-inventory check <object-id> --export report.json

# Include RBAC inherited through group memberships
./azure-rbac-inventory check <object-id> --include-group-rbac

# Include access package assignments and requests
./azure-rbac-inventory check <object-id> --include-access-packages

# Search by display name or pattern
./azure-rbac-inventory check "spn-myapp*" --cloud AzureUSGovernment

# Check a managed identity by name
./azure-rbac-inventory check "my-managed-identity" --type managed-identity

# Batch check from a file
./azure-rbac-inventory check --file identities.txt --cloud AzureUSGovernment

# Use device-code auth for SSH/headless environments
./azure-rbac-inventory check <object-id> --auth device-code

# Compare two identities side-by-side
./azure-rbac-inventory compare <id-A> <id-B>

# Model compare: one baseline vs. multiple targets
./azure-rbac-inventory compare --model <model-id> <target-1> <target-2>
```

## Usage

```
azure-rbac-inventory check <identity> [flags]

Global Flags:
      --cloud string           Azure cloud name (AzureCloud|AzureUSGovernment|AzureChinaCloud) (default "AzureCloud")
      --tenant string          Tenant ID (uses default from credential if not set)
      --auth string            Authentication method (interactive|device-code) (default "interactive")
  -o, --output string          Output format (table|json|csv|markdown) (default "table")
      --subscriptions string   Comma-separated subscription IDs (default: all accessible)
      --include-group-rbac     Also query RBAC role assignments inherited through group memberships (group list always shown)
      --include-access-packages  Query access package assignments and requests (requires EntitlementManagement.Read.All)
      --file string            Read identities from file (one per line)
      --type string            Filter identity type (spn|user|group|managed-identity|app|all) (default "all")
      --export string          Export to file (format inferred from extension: .csv, .html, .md, .xlsx, .json)
      --per-identity           Separate output per identity (default false)
      --max-results int        Max search results for pattern matching (default 50)
      --concurrency int        Max concurrent identity checks (default 10)
      --timeout duration       Global execution timeout (default 30m)
      --json-file string       [Deprecated] Export results to JSON file — use --export report.json instead
  -v, --verbose                Verbose output
  -h, --help                   help for azure-rbac-inventory

# Version (root command only)
azure-rbac-inventory --version
```

> **Note:** The `--cloud` flag value is **case-insensitive**. The following are all valid:
> `AzureCloud`, `azurecloud`, `AZURECLOUD`, `AzureUSGovernment`, `azureusgovernment`, `AzureChinaCloud`.

## Compare

Compare RBAC assignments, Entra ID directory roles, group memberships, and access packages between identities. Two modes are available:

### 1:1 Compare

Compare two identities side-by-side:

```bash
azure-rbac-inventory compare <id-A> <id-B>
```

The output shows four sections (RBAC, Directory Roles, Groups, Access Packages), each with three columns: items unique to identity A, items shared, and items unique to identity B.

```bash
# Compare two SPNs
azure-rbac-inventory compare aaaaaaaa-1111-2222-3333-444444444444 bbbbbbbb-5555-6666-7777-888888888888

# Compare by display name
azure-rbac-inventory compare "spn-prod-app" "spn-staging-app"

# Compare in Azure Government
azure-rbac-inventory compare <id-A> <id-B> --cloud AzureUSGovernment

# Export comparison to HTML with visual diff
azure-rbac-inventory compare <id-A> <id-B> --export diff.html

# Export comparison to JSON
azure-rbac-inventory compare <id-A> <id-B> --export diff.json
```

### Model Compare (1:N)

Use `--model` to designate one identity as the baseline and compare multiple targets against it. Each target is compared independently to the model, showing match percentage and drift:

```bash
azure-rbac-inventory compare --model <model-id> <target-1> <target-2> <target-3>
```

```bash
# Compare a golden SPN against several targets
azure-rbac-inventory compare --model "spn-golden-config" "spn-team-a" "spn-team-b" "spn-team-c"

# Load targets from a file
azure-rbac-inventory compare --model <model-id> --file targets.csv

# Load targets from JSON
azure-rbac-inventory compare --model <model-id> --file targets.json

# Export model compare results to HTML
azure-rbac-inventory compare --model <model-id> --file targets.csv --export drift-report.html

# Azure Government with specific subscriptions
azure-rbac-inventory compare --model <model-id> --file targets.txt \
  --cloud AzureUSGovernment --subscriptions "sub-1,sub-2"
```

The `--file` flag accepts the same formats as `check` (CSV, JSON, plain text). See [File Input Formats](#file-input-formats) for details.

### Match Percentage

Match% is calculated per section (RBAC, Directory Roles, Groups, Access Packages):

```
match% = shared items / max(total_A, total_B) × 100
```

- **100%** — The two identities have identical assignments in that section
- **0%** — No overlap at all

### RBAC Comparison Keys

RBAC assignments are compared by **RoleName + ScopeType** (e.g., `Contributor @ Subscription`). Specific scope IDs (subscription GUIDs, resource group names) are ignored during comparison because identities in different environments typically operate on different subscriptions. This means two identities both having `Contributor` at the subscription level are considered a match, even if the subscription IDs differ.

### Workload-Aware Comparison

When SPNs follow a naming convention that embeds a workload identifier (e.g., `spn-fedrampmod-wkld-axonius`), the tool can perform **cross-workload** scope comparison. Instead of comparing raw scope IDs, scopes are normalized by replacing the workload token with `{workload}`, so assignments on different but structurally equivalent subscriptions are matched correctly.

**How it works:**

1. **Primary detection** — The tool looks for a `wkld-{name}` segment in the SPN display name and validates the extracted name against the SPN's subscription display names.
2. **Fallback** — If `wkld-` is not present, the tool finds the longest common segment between the SPN name and its subscription names.
3. **Override** — Use `--workload-key` to explicitly set the workload name for the golden SPN.
4. **Normalization** — Scopes containing the workload token are normalized to `{workload}`, enabling cross-workload comparison. Scopes without the workload token (shared/common subscriptions) are compared exactly.

**How scope normalization works:**

```
Golden: spn-fedrampmod-wkld-axonius → workload = "axonius"
  Reader on azg-sub-axonius-hub-01     → Reader|azg-sub-{workload}-hub-01
  Contributor on azg-sub-axonius-spoke-01 → Contributor|azg-sub-{workload}-spoke-01

Target: spn-fedrampmod-wkld-zscaler → workload = "zscaler"
  Reader on azg-sub-zscaler-hub-01     → Reader|azg-sub-{workload}-hub-01  ✓ MATCH
  Contributor on azg-sub-zscaler-spoke-01 → Contributor|azg-sub-{workload}-spoke-01  ✓ MATCH
```

**Examples:**

```bash
# Auto-detect workload names from SPN naming conventions
azure-rbac-inventory compare --model spn-fedrampmod-wkld-axonius \
  spn-fedrampmod-wkld-zscaler spn-fedrampmod-wkld-adh \
  --cloud AzureUSGovernment

# Explicit workload key for the golden SPN
azure-rbac-inventory compare --model spn-fedrampmod-wkld-axonius \
  --workload-key axonius \
  --file targets.csv --cloud AzureUSGovernment

# Export workload comparison to HTML
azure-rbac-inventory compare --model spn-fedrampmod-wkld-axonius \
  spn-fedrampmod-wkld-zscaler --export workload-diff.html
```

### Compare Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--model` | Baseline identity for 1:N model compare | — |
| `--file` | Load target identities from file (CSV, JSON, or text) | — |
| `--export` | Export comparison to file (`.html` or `.json`) | — |
| `--workload-key` | Explicit workload name for the golden SPN | Auto-detected |

All global flags (`--cloud`, `--tenant`, `--auth`, `--subscriptions`, `--timeout`, `--verbose`, etc.) also apply to `compare`.

## Pattern Search

Instead of requiring an exact object ID, you can search by display name or wildcard pattern:

```bash
# Exact display name match
azure-rbac-inventory check "my-app-spn"

# Prefix wildcard — matches anything starting with "spn-myapp"
azure-rbac-inventory check "spn-myapp*" --cloud AzureUSGovernment --auth interactive

# Contains wildcard — matches anything containing "prod"
azure-rbac-inventory check "*prod*" --type spn --max-results 10

# Managed identity by name
azure-rbac-inventory check "my-managed-identity" --type managed-identity
```

Use `--type` to filter by identity type: `spn`, `user`, `group`, `managed-identity`, `app`, or `all` (default).
Use `--max-results` to limit search results (default: 50).

## File Input

Check multiple identities at once by reading from a file:

```bash
azure-rbac-inventory check --file identities.csv --cloud AzureUSGovernment
azure-rbac-inventory check --file identities.json --export report.html
azure-rbac-inventory check --file identities.txt --per-identity --export reports.csv
```

Use `--per-identity` to produce separate output sections per identity.
Use `--concurrency` to control how many identities are checked in parallel (default: 10).

## File Input Formats

The `--file` flag supports three formats, auto-detected by file extension:

| Extension | Format | Parser |
|-----------|--------|--------|
| `.csv` | Comma-separated values | CSV with header row |
| `.json` | JSON | `{"identities": [...]}` structure |
| `.txt` (or any other) | Plain text | One ID per line |

### CSV Format

Requires a header row with an `id` column (case-insensitive). Optional columns: `type`, `label`. Column order does not matter. Values are trimmed of leading/trailing whitespace.

```csv
id,type,label
12345678-aaaa-bbbb-cccc-111111111111,spn,Production Service Principal
12345678-aaaa-bbbb-cccc-222222222222,,Production SPN
spn-myapp*,spn,All Application SPNs
john.doe@contoso.com,user,John Doe
```

### JSON Format

Requires a top-level `identities` array. Each entry must have an `id` field. Optional fields: `type`, `label`.

```json
{
  "identities": [
    {"id": "12345678-aaaa-bbbb-cccc-111111111111", "type": "spn", "label": "Production Service Principal"},
    {"id": "12345678-aaaa-bbbb-cccc-222222222222", "label": "Production SPN"},
    {"id": "spn-myapp*", "type": "spn", "label": "All Application SPNs"},
    {"id": "john.doe@contoso.com", "type": "user", "label": "John Doe"}
  ]
}
```

### Plain Text Format

One identity per line. Lines starting with `#` are comments. Empty lines are ignored.

```
# Identity list for RBAC audit
# One ID or pattern per line

12345678-aaaa-bbbb-cccc-111111111111
12345678-aaaa-bbbb-cccc-222222222222
spn-myapp*
john.doe@contoso.com
```

### Example Files

See the [`examples/`](examples/) directory for sample input files in all three formats:

- [`sample-input.csv`](examples/sample-input.csv)
- [`sample-input.json`](examples/sample-input.json)
- [`sample-input.txt`](examples/sample-input.txt)

## Export Formats

Export results to a file — the format is inferred from the file extension:

```bash
azure-rbac-inventory check <id> --export report.csv
azure-rbac-inventory check <id> --export report.html
azure-rbac-inventory check <id> --export report.md
azure-rbac-inventory check <id> --export report.xlsx
azure-rbac-inventory check <id> --export report.json
```

Console output format can be set independently with `--output`:

```bash
azure-rbac-inventory check <id> --output json
azure-rbac-inventory check <id> --output csv
azure-rbac-inventory check <id> --output markdown
```

## Flags Reference

| Flag | Description | Default | Env Var |
|------|-------------|---------|---------|
| `--file` | Read identities from file | — | — |
| `--type` | Filter identity type (`spn\|user\|group\|managed-identity\|app\|all`) | `all` | — |
| `--export` | Export to file (format from extension: `.csv`, `.html`, `.md`, `.xlsx`, `.json`) | — | — |
| `--per-identity` | Separate output per identity | `false` | — |
| `--max-results` | Max search results | `50` | — |
| `--concurrency` | Max concurrent checks | `10` | — |
| `--timeout` | Global execution timeout | `30m` | — |
| `--auth` | Authentication method (`interactive\|device-code\|environment\|managed-identity\|azurecli`) | `interactive` | `AZURE_RBAC_AUTH` |
| `--output` | Console format: `table\|json\|csv\|markdown` | `table` | — |
| `--cloud` | Azure cloud name | `AzureCloud` | `AZURE_RBAC_CLOUD` |
| `--tenant` | Tenant ID | auto-detected | `AZURE_TENANT_ID` |
| `--subscriptions` | Comma-separated subscription IDs | all accessible | `AZURE_RBAC_SUBSCRIPTIONS` |
| `--include-group-rbac` | Also query RBAC inherited through group memberships | `false` | — |
| `--include-access-packages` | Query access package assignments and requests | `false` | — |
| `--json-file` | **Deprecated.** Export results to JSON file — use `--export report.json` instead | — | — |
| `--verbose` | Verbose output | `false` | — |

> **Environment variables** provide defaults for flags. Flag values always take precedence when explicitly set.

## Authentication

Azure RBAC Inventory uses **interactive browser authentication** by default. On first run, a browser window opens for sign-in. Tokens are cached locally by the Azure Identity SDK (via MSAL) so subsequent runs authenticate silently.

| `--auth` value | Method | Use case |
|----------------|--------|----------|
| `interactive` | Interactive browser login (default) | Opens a browser for sign-in; tokens are cached locally |
| `device-code` | Device code flow | For environments without a browser (SSH, containers) |
| `environment` | Service principal (env vars) | CI/CD pipelines — uses `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |
| `managed-identity` | Azure Managed Identity | Azure-hosted runners (Azure DevOps agents, AKS, Azure VMs) |
| `azurecli` | Azure CLI credential | CI/CD pipelines using service principal `az login` (GitHub Actions `azure/login`, Azure DevOps service connections) |

```bash
# Default: interactive browser login
azure-rbac-inventory check <id>

# Device code flow for headless environments
azure-rbac-inventory check <id> --auth device-code

# CI/CD: service principal via environment variables
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<secret>"
export AZURE_TENANT_ID="<tenant-id>"
azure-rbac-inventory check <id> --auth environment --output json

# CI/CD: managed identity (Azure-hosted runners)
azure-rbac-inventory check <id> --auth managed-identity --output json

# CI/CD: service principal az login (gets both Graph + ARM scopes)
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
azure-rbac-inventory check <id> --auth azurecli --output json
```

> **Tip:** For interactive auth, the tool requires delegated permissions — consent to `Directory.Read.All` when prompted. For CI/CD auth methods (`environment`, `managed-identity`, `azurecli`), use **application permissions** granted via app registration in Entra ID. For access package queries (`--include-access-packages`), `EntitlementManagement.Read.All` is also needed.

> **Important:** `--auth azurecli` is designed for **service principal** login in CI/CD pipelines. Interactive `az login` sessions scope to a single resource and may fail when the tool needs both Graph and ARM tokens. For interactive use, prefer `--auth interactive` (the default).

### CI/CD Pipeline Examples

#### GitHub Actions

```yaml
- name: Azure Login
  uses: azure/login@v2
  with:
    creds: ${{ secrets.AZURE_CREDENTIALS }}

- name: RBAC Audit
  run: |
    azure-rbac-inventory check <id> \
      --auth azurecli \
      --output json \
      --export rbac-report.json
```

Or with service principal environment variables:

```yaml
- name: RBAC Audit
  env:
    AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
    AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
    AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
  run: |
    azure-rbac-inventory check <id> \
      --auth environment \
      --output json \
      --export rbac-report.json
```

#### Azure DevOps

```yaml
- task: AzureCLI@2
  inputs:
    azureSubscription: 'my-service-connection'
    scriptType: bash
    scriptLocation: inlineScript
    inlineScript: |
      azure-rbac-inventory check <id> \
        --auth azurecli \
        --output json \
        --export $(Build.ArtifactStagingDirectory)/rbac-report.json
```

## Required Permissions

The identity running this tool needs:

| Permission | Scope | Purpose | Required? |
|------------|-------|---------|-----------|
| `Reader` | Subscriptions / Management Groups | Query RBAC role assignments | Yes |
| `Directory.Read.All` | Microsoft Graph | Resolve identities, query directory roles and group memberships | Yes |
| `EntitlementManagement.Read.All` | Microsoft Graph | Query access package assignments and requests | Optional — only needed with `--include-access-packages` |

> **Tip:** The tool uses interactive browser authentication by default. Graph permissions are granted as **delegated permissions** — consent to them when prompted during sign-in.

## Cloud Endpoints

| Service | AzureCloud | AzureUSGovernment | AzureChinaCloud |
|---------|-----------|------------|-----------------|
| ARM | `management.azure.com` | `management.usgovcloudapi.net` | `management.chinacloudapi.cn` |
| Graph | `graph.microsoft.com` | `graph.microsoft.us` | `microsoftgraph.chinacloudapi.cn` |
| Login | `login.microsoftonline.com` | `login.microsoftonline.us` | `login.chinacloudapi.cn` |

## Testing

```bash
# Run all tests
go test ./...

# Run tests with verbose output
make test

# Run tests with race detection
make test-race
# or directly:
go test -race ./... -count=1
```

> **Note:** The `-race` flag requires CGO and is not available on all platforms (e.g., `windows/arm64`).
> Race detection is recommended to run in CI on `linux/amd64` where CGO is available by default.

## Build from Source

Requires Go 1.26+.

```bash
# Build for current platform
go build -o azure-rbac-inventory.exe .

# Cross-compile for all platforms (requires make)
# NOTE: The Makefile uses Windows cmd.exe syntax (set GOOS=...).
# On Linux/macOS, use standard env vars instead: GOOS=linux GOARCH=amd64 go build ...
make all

# Outputs in dist/:
#   azure-rbac-inventory-windows-amd64.exe
#   azure-rbac-inventory-windows-arm64.exe
#   azure-rbac-inventory-linux-amd64
#   azure-rbac-inventory-linux-arm64
#   azure-rbac-inventory-darwin-amd64
#   azure-rbac-inventory-darwin-arm64
```

## Troubleshooting

### Authentication failures

If you see `authentication failed:` errors:

- **Browser did not open** — On headless systems (SSH, containers), use `--auth device-code` instead.
- **Wrong tenant** — If you're getting `authorization_request_denied` errors, verify you're authenticating against the correct tenant with `--tenant <tenant-id>`.

### Azure CLI (`--auth azurecli`) errors

**InteractionRequired errors:** Azure CLI interactive login (`az login`) scopes sessions to a single resource. The tool needs both Graph and ARM access, which can cause `InteractionRequired` failures. Solutions:

- **For CI/CD (recommended):** Use service principal login, which grants access to all resources the SPN has permissions for:
  ```bash
  az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
  ```
- **For interactive use:** Use `--auth interactive` (the default) instead of `--auth azurecli`.
- **Stale token cache:** If you previously ran `az login --scope`, the token cache may be corrupted. Clear it:
  ```bash
  az account clear
  az login
  ```

**403 Authorization_RequestDenied with SPN:** The service principal is missing Graph API permissions. Grant `Directory.Read.All` as an **application permission**:
```bash
# Get your SPN's app ID
az ad sp list --display-name "<spn-name>" --query "[].appId" -o tsv

# Grant Directory.Read.All (Application permission)
az ad app permission add --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

# Admin consent (requires Global Admin or Privileged Role Admin)
az ad app permission admin-consent --id <app-id>
```

> **Note:** Permission changes may take a few minutes to propagate. If you still see 403 after granting, wait 2-5 minutes and retry.

### "Token expired" / "AADSTS700024"

The cached token expired. Clear the token cache and re-authenticate:

```bash
# Linux / macOS
rm -f ~/.azure/msal_token_cache*

# Windows (PowerShell)
Remove-Item "$env:USERPROFILE\.azure\msal_token_cache*" -ErrorAction SilentlyContinue
```

Then run the tool again — a new browser prompt will appear for sign-in.

### 403 Forbidden on Graph API

The tool queries Microsoft Graph for directory roles, group memberships, and optionally access packages. If you see `Graph API error (HTTP 403)`:

- **Missing `Directory.Read.All`** — Required for identity resolution, directory role lookups, and group membership queries.
- **Missing `EntitlementManagement.Read.All`** — Required when using `--include-access-packages`. Without it, access package queries will fail with 403 errors. If you don't need access packages, simply omit the flag.
- The tool continues running even when individual queries fail (partial failure model). Check the `Warning:` messages in stderr output to identify which permissions are missing.

### Empty results

- **"0 found" is genuine** — If a section shows `0 found` with no warning, the query succeeded and the identity truly has no assignments of that type.
- **Warning messages indicate API failure** — If you see `Warning: <section> query failed:` in the stderr output, the query did not succeed. The `0 found` count in that case does not mean the identity has no assignments — it means the tool could not retrieve them. Fix the underlying permission or network issue.

### "No subscriptions found"

The identity may not have `Reader` on any subscription. Use `--subscriptions` to specify subscription IDs explicitly:

```bash
azure-rbac-inventory check <id> --subscriptions "sub-id-1,sub-id-2"
```

### "Connection refused" / timeout errors

Verify network connectivity to Azure ARM and Graph endpoints. Corporate firewalls and proxies may block these. See [Cloud Endpoints](#cloud-endpoints) for the hostnames that must be reachable.

```bash
# Test ARM connectivity
curl -s https://management.azure.com/tenants?api-version=2020-01-01

# Test Graph connectivity
curl -s https://graph.microsoft.com/v1.0/$metadata
```

### "identity not found"

The provided ID doesn't match any object in the directory. Verify:
- The GUID is correct (no typos, no extra whitespace)
- You're targeting the right tenant (`--tenant <tenant-id>`)
- You're using the right cloud (`--cloud AzureUSGovernment` for Gov tenants)

### Duplicate RBAC entries

The tool deduplicates by default. If you still see duplicates when using `--include-group-rbac`, the role may be assigned both directly to the identity *and* through a group membership. Both are legitimate assignments and are shown with their respective assignment type (`Direct` vs. the group name).

### Slow performance with many subscriptions

RBAC queries run per-subscription. To improve performance:
- Use `--subscriptions sub-id-1,sub-id-2` to limit scope to specific subscriptions
- Increase `--concurrency` (default: 10) for parallel processing

### Azure Government cloud

To use with Azure Government:

```bash
# 1. Set your Azure CLI to the Government cloud
az cloud set --name AzureUSGovernment
az login

# 2. Pass --cloud flag to azure-rbac-inventory
./azure-rbac-inventory check <object-id> --cloud AzureUSGovernment
```

Both steps are required. The `--cloud` flag tells azure-rbac-inventory which Graph and ARM endpoints to use, but `az login` must also be authenticated against the Government cloud. If you see `invalid_resource` or endpoint errors, verify both are set consistently.

## FAQ

**Q: Can I check multiple identities at once?**
Yes. Use `--file` with a CSV, JSON, or text file containing identity IDs or patterns. See [File Input Formats](#file-input-formats) for details.

**Q: Does this tool make any changes?**
No. Azure RBAC Inventory is strictly read-only. It only queries Azure ARM and Microsoft Graph APIs. No modifications are made to any resources, roles, or assignments.

**Q: What identity types are supported?**
Users, service principals (SPNs), managed identities, app registrations, and groups. Use `--type` to filter by a specific type.

**Q: How do I include access package data?**
Use `--include-access-packages`. This requires the `EntitlementManagement.Read.All` Graph permission. Without the flag, access package sections show "Skipped" instead of querying.

**Q: Can I use this with Azure Government?**
Yes. Pass `--cloud AzureUSGovernment`. Make sure `az login` is also targeting the Government cloud (`az cloud set --name AzureUSGovernment`). See [Azure Government cloud](#azure-government-cloud).

**Q: How do I check a managed identity?**
Pass the object ID directly, or search by name with `--type managed-identity`:
```bash
azure-rbac-inventory check "my-managed-identity" --type managed-identity
```

**Q: Why are RBAC results showing 0 when I know there are assignments?**
Verify the running identity has `Reader` access on the target subscriptions. Also check if you need `--subscriptions` to specify particular subscription IDs. Use `--verbose` to see which subscriptions were queried.

**Q: Can I export results for a manager or auditor?**
Yes. Use `--export report.html` for a polished HTML report, or `--export report.xlsx` for Excel. CSV and Markdown are also supported.

**Q: What's the difference between Direct and Inherited assignments?**
Direct means the role is assigned directly to the identity. Inherited means it came through a group membership (shown when using `--include-group-rbac`).

**Q: Does the tool work in CI/CD pipelines?**
Yes. Three non-interactive authentication methods are available:

| Method | Flag | When to use |
|---|---|---|
| Service principal | `--auth environment` | Set `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` as env vars |
| Managed identity | `--auth managed-identity` | Azure-hosted compute (VMs, AKS, Azure DevOps agents) |
| Azure CLI | `--auth azurecli` | After `az login --service-principal` or `azure/login@v2` GitHub Action |

The service principal must have `Directory.Read.All` (Application permission) and `Reader` on target subscriptions. See [Troubleshooting > Azure CLI errors](#azure-cli---auth-azurecli-errors) if you encounter 403 or InteractionRequired errors.

Use `--output json` for machine-readable output:
```bash
azure-rbac-inventory check <id> --auth environment --output json --export report.json
```

**Q: What happens if I don't have permissions to all subscriptions?**
The tool queries all accessible subscriptions by default. Subscriptions you can't access are silently skipped. Use `--verbose` to see which subscriptions were queried.

**Q: Can I limit which subscriptions are checked?**
Yes. Use `--subscriptions` to check only specific subscriptions:
```bash
azure-rbac-inventory check <id> --subscriptions "sub-id-1,sub-id-2"
```

**Q: How does `compare` differ from running `check` on two identities?**
`check` produces independent reports per identity. `compare` aligns results side-by-side, highlights shared vs. unique assignments, and calculates match percentages. The `--model` flag extends this to 1:N comparisons with drift detection.

**Q: Why does compare ignore specific scope IDs for RBAC?**
Identities in different environments (dev vs. prod) typically operate on different subscriptions. Comparing by `RoleName + ScopeType` (e.g., `Contributor @ Subscription`) captures whether the same *kind* of access is granted, without false negatives from differing subscription GUIDs.

**Q: Can I compare identities across clouds?**
No. Both identities must be in the same tenant and cloud. The comparison queries run against a single set of ARM/Graph endpoints.

**Q: What naming conventions does workload-aware comparison require?**
SPNs and subscriptions must share a common workload identifier. The tool tries to extract it from the `wkld-{name}` pattern in SPN names and validates it against subscription display names. If your naming doesn't follow a discernible pattern, use `--workload-key` to specify it explicitly. If no workload is detected, the tool falls back to scope-type-only comparison.

**Q: What happens if a target SPN's workload name can't be detected?**
The tool warns and falls back to non-workload comparison for that specific target. Other targets with detectable workload names continue using workload-aware comparison.

## Notes & Limitations

- **Concurrency** — The tool runs top-level queries (RBAC, directory roles, group memberships, and optionally access packages) in parallel for speed. RBAC subscription queries are additionally parallelized with a concurrency limit of 10 subscriptions at a time. Progress messages are printed to stderr and may interleave.
- **Application identities** — Application registrations (`#microsoft.graph.application`) do not support group membership lookups via the Graph API. The group memberships section will return empty for these identities. Service principals associated with the same app registration *do* support group membership lookups.
- **Access package request limit** — When using `--include-access-packages`, access package requests are limited to the **50 most recent** results (ordered by `createdDateTime desc`). If the identity has a longer request history, older requests are not returned.
- **Dual output** — Use `--export results.json` together with `--output table` to get human-readable table output on screen and machine-readable JSON saved to a file simultaneously. The legacy `--json-file` flag still works but is deprecated — use `--export report.json` instead.
- **Verbose mode** — `--verbose` currently only adds detail to group RBAC query warnings (e.g., when `--include-group-rbac` encounters a permission error on a specific group). It does not affect other sections.
- **Eventual consistency** — All Graph API requests include the `ConsistencyLevel: eventual` header. This enables advanced query features but means results may be slightly stale (typically seconds, occasionally minutes) compared to the most recent directory changes.

## Security Considerations

- **Read-only** — This tool performs only read operations against Azure ARM and Microsoft Graph APIs. It does not create, modify, or delete any resources.
- **No secrets stored** — The tool does not store or cache any credentials. Authentication is delegated to the Azure Identity SDK which manages token lifecycle.
- **Token caching** — Tokens are cached locally by the Azure Identity SDK (via MSAL) to avoid repeated login prompts. Cache files are stored with restricted permissions.
- **Output sensitivity** — Report outputs (JSON, HTML, CSV, XLSX, etc.) contain identity information including object IDs, role assignments, and group memberships. Treat exported files as sensitive and handle according to your organization's data classification policies.
- **Network** — All API calls use HTTPS. The tool validates pagination URLs to prevent token theft via malicious redirect.

## Example Output

```
  ======================================================
   Azure RBAC Inventory - Identity Report
  ======================================================

    Name:       my-app-spn
    Object ID:  aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    Type:       ServicePrincipal
    App ID:     11111111-2222-3333-4444-555555555555
    Cloud:      AzureCloud

  [RBAC] Azure Role Assignments (5)
  ------------------------------------------------------

    ► Subscription: abc-def-123 (3)
        Contributor                              [Direct]
        Key Vault Administrator                  [Direct]
        Storage Blob Data Contributor            [Direct]

    ► Resource Group: rg-prod-eastus (1)
        Reader                                   [Direct]

    ► Key Vaults (1)
        Key Vault Secrets Officer  → kv-prod-secrets  Direct

  [ROLES] Entra ID Directory Roles (1)
  ------------------------------------------------------
    * Application Administrator  [Active]

  [PACKAGES] Access Package Assignments (0)
  ------------------------------------------------------
    Skipped (use --include-access-packages to query)

  [REQUESTS] Access Package Requests (0)
  ------------------------------------------------------
    Skipped (use --include-access-packages to query)

  [GROUPS] Group Memberships (2)
  ------------------------------------------------------
    GROUP                          TYPE               MEMBERSHIP
    ------------------------------  ---------------    ------------
    DevOps-Team                    Security           Direct
    All-Engineers                  Microsoft 365      Transitive
```

## License

MIT
