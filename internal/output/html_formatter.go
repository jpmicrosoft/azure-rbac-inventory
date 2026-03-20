package output

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// HTMLFormatter renders reports as self-contained HTML files.
type HTMLFormatter struct{}

func (HTMLFormatter) FileExtension() string { return ".html" }

// rbacHTMLRoleGroup represents a role within a resource type category,
// with all the resources it applies to.
type rbacHTMLRoleGroup struct {
	RoleName       string
	AssignmentType string
	Resources      []string // resource names/IDs this role applies to
}

// rbacHTMLGroup represents a resource type category with roles grouped inside.
type rbacHTMLGroup struct {
	Name       string // e.g., "Subscriptions", "Private DNS Zones"
	Priority   int
	TotalItems int // total role assignments in this group
	RoleGroups []rbacHTMLRoleGroup
}

// extractResourceCategory derives a resource type category name, the individual
// resource identifier, and a sort priority from an ARM scope path.
func extractResourceCategory(scope, scopeType string) (category, resourceID string, priority int) {
	parts := strings.Split(strings.TrimRight(scope, "/"), "/")

	switch scopeType {
	case "Management Group":
		for i, p := range parts {
			if p == "managementGroups" && i+1 < len(parts) {
				return "Management Groups", parts[i+1], 0
			}
		}
		return "Management Groups", "", 0
	case "Subscription":
		for i, p := range parts {
			if p == "subscriptions" && i+1 < len(parts) {
				return "Subscriptions", parts[i+1], 1
			}
		}
		return "Subscriptions", "", 1
	case "Resource Group":
		for i, p := range parts {
			if p == "resourceGroups" && i+1 < len(parts) {
				return "Resource Groups", parts[i+1], 2
			}
		}
		return "Resource Groups", "", 2
	case "Resource":
		lastProviderIdx := -1
		for i, p := range parts {
			if p == "providers" {
				lastProviderIdx = i
			}
		}
		if lastProviderIdx >= 0 && lastProviderIdx+2 < len(parts) {
			remaining := parts[lastProviderIdx+2:]
			var deepType, deepName string
			for i := 0; i+1 < len(remaining); i += 2 {
				deepType = remaining[i]
				deepName = remaining[i+1]
			}
			if deepType != "" {
				return friendlyResourceType(deepType), deepName, 3
			}
		}
		return "Resources", "", 3
	}
	return "Other", "", 4
}

// groupRBACForHTML groups RBAC assignments into a two-level hierarchy:
// resource type category → role name → list of resources.
func groupRBACForHTML(assignments []rbac.RoleAssignment) []rbacHTMLGroup {
	type roleKey struct {
		roleName       string
		assignmentType string
	}
	type categoryEntry struct {
		name       string
		priority   int
		totalItems int
		roleOrder  []roleKey
		roles      map[roleKey][]string
	}

	catOrder := []string{}
	categories := map[string]*categoryEntry{}

	for _, a := range assignments {
		cat, resID, priority := extractResourceCategory(a.Scope, a.ScopeType)

		entry, ok := categories[cat]
		if !ok {
			entry = &categoryEntry{
				name:     cat,
				priority: priority,
				roles:    make(map[roleKey][]string),
			}
			categories[cat] = entry
			catOrder = append(catOrder, cat)
		}
		entry.totalItems++

		rk := roleKey{roleName: a.RoleName, assignmentType: a.AssignmentType}
		if _, exists := entry.roles[rk]; !exists {
			entry.roleOrder = append(entry.roleOrder, rk)
		}
		if resID != "" {
			entry.roles[rk] = append(entry.roles[rk], resID)
		}
	}

	// Sort categories by priority, then alphabetically
	sort.SliceStable(catOrder, func(i, j int) bool {
		ci, cj := categories[catOrder[i]], categories[catOrder[j]]
		if ci.priority != cj.priority {
			return ci.priority < cj.priority
		}
		return ci.name < cj.name
	})

	result := make([]rbacHTMLGroup, 0, len(catOrder))
	for _, key := range catOrder {
		entry := categories[key]

		// Sort roles alphabetically within each category
		sort.SliceStable(entry.roleOrder, func(i, j int) bool {
			ri, rj := entry.roleOrder[i], entry.roleOrder[j]
			if ri.roleName != rj.roleName {
				return ri.roleName < rj.roleName
			}
			return ri.assignmentType < rj.assignmentType
		})

		roleGroups := make([]rbacHTMLRoleGroup, 0, len(entry.roleOrder))
		for _, rk := range entry.roleOrder {
			resources := entry.roles[rk]
			sort.Strings(resources)
			roleGroups = append(roleGroups, rbacHTMLRoleGroup{
				RoleName:       rk.roleName,
				AssignmentType: rk.assignmentType,
				Resources:      resources,
			})
		}

		result = append(result, rbacHTMLGroup{
			Name:       entry.name,
			Priority:   entry.priority,
			TotalItems: entry.totalItems,
			RoleGroups: roleGroups,
		})
	}
	return result
}

// htmlIdentityData pairs a report with its pre-computed RBAC groups.
type htmlIdentityData struct {
	Report     *reportpkg.Report
	RBACGroups []rbacHTMLGroup
}

// htmlReportData is the template context for a single report.
type htmlReportData struct {
	Report     *reportpkg.Report
	RBACGroups []rbacHTMLGroup
	Generated  string
}

// htmlMultiData is the template context for multiple reports.
type htmlMultiData struct {
	Identities []htmlIdentityData
	Generated  string
}

func (f HTMLFormatter) FormatReport(rpt *reportpkg.Report) ([]byte, error) {
	tmpl, err := template.New("report").Parse(htmlSingleTemplate)
	if err != nil {
		return nil, fmt.Errorf("html template parse error: %w", err)
	}
	var buf bytes.Buffer
	data := htmlReportData{
		Report:     rpt,
		RBACGroups: groupRBACForHTML(rpt.RBACAssignments),
		Generated:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("html template execute error: %w", err)
	}
	return buf.Bytes(), nil
}

func (f HTMLFormatter) FormatMultiReport(reports []*reportpkg.Report) ([]byte, error) {
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}
	tmpl, err := template.New("multi").Funcs(funcMap).Parse(htmlMultiTemplate)
	if err != nil {
		return nil, fmt.Errorf("html template parse error: %w", err)
	}
	var buf bytes.Buffer
	identities := make([]htmlIdentityData, len(reports))
	for i, rpt := range reports {
		identities[i] = htmlIdentityData{
			Report:     rpt,
			RBACGroups: groupRBACForHTML(rpt.RBACAssignments),
		}
	}
	data := htmlMultiData{
		Identities: identities,
		Generated:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("html template execute error: %w", err)
	}
	return buf.Bytes(), nil
}

const htmlStyle = `
<style>
  :root {
    --primary: #2B5797;
    --primary-light: #3a6fb7;
    --bg: #f5f7fa;
    --card-bg: #ffffff;
    --text: #333333;
    --text-light: #666666;
    --border: #dee2e6;
    --success: #28a745;
    --warning-bg: #fff3cd;
    --warning-border: #ffc107;
    --warning-text: #856404;
    --badge-direct: #28a745;
    --badge-inherited: #6c757d;
    --badge-active: #28a745;
    --badge-expired: #dc3545;
    --badge-pending: #ffc107;
    --badge-delivered: #17a2b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 20px;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { color: var(--primary); margin-bottom: 5px; font-size: 1.8em; }
  .subtitle { color: var(--text-light); font-size: 0.9em; margin-bottom: 20px; }
  .card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  }
  .identity-header {
    background: linear-gradient(135deg, #1a3a6c 0%, #2B5797 50%, #3a6fb7 100%);
    color: #fff;
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .identity-header h2 { color: #fff; margin-bottom: 10px; font-size: 1.5em; }
  .identity-meta { display: flex; flex-wrap: wrap; gap: 20px; }
  .identity-meta .meta-item { font-size: 0.9em; }
  .identity-meta .meta-label { opacity: 0.8; font-size: 0.85em; display: block; }
  .identity-meta .meta-value { font-weight: 600; }
  details {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }
  summary {
    padding: 14px 20px;
    cursor: pointer;
    font-weight: 600;
    font-size: 1.05em;
    color: var(--primary);
    list-style: none;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  summary::before { content: '\25B6'; font-size: 0.7em; transition: transform 0.2s; }
  details[open] > summary::before { transform: rotate(90deg); }
  summary::-webkit-details-marker { display: none; }
  .section-count {
    background: var(--primary);
    color: #fff;
    border-radius: 12px;
    padding: 2px 10px;
    font-size: 0.78em;
    font-weight: 700;
    margin-left: auto;
  }
  .section-body { padding: 0 20px 20px; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9em;
  }
  th {
    background: var(--primary);
    color: #fff;
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
    white-space: nowrap;
  }
  td { padding: 9px 12px; border-bottom: 1px solid var(--border); }
  tr:nth-child(even) td { background: #f8f9fa; }
  tr:hover td { background: #e9ecef; }
  .mono { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace; font-size: 0.88em; letter-spacing: -0.02em; }
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.78em;
    font-weight: 600;
    color: #fff;
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
  .badge-direct { background: var(--badge-direct); }
  .badge-inherited { background: var(--badge-inherited); }
  .badge-transitive { background: var(--badge-inherited); }
  .badge-active { background: var(--badge-active); }
  .badge-expired { background: var(--badge-expired); }
  .badge-pending { background: var(--badge-pending); color: #333; }
  .badge-delivered { background: var(--badge-delivered); }
  .badge-default { background: #6c757d; }
  .empty-msg { color: var(--text-light); font-style: italic; padding: 12px 0; }
  .warnings {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 20px;
  }
  .warnings h3 { color: var(--warning-text); margin-bottom: 8px; }
  .warnings ul { margin-left: 20px; color: var(--warning-text); }
  .warnings li { margin-bottom: 4px; }
  .toc { margin-bottom: 24px; }
  .toc h3 { margin-bottom: 12px; }
  .toc-list { list-style: none; padding: 0; margin: 0; }
  .toc-entry {
    display: flex;
    align-items: center;
    padding: 10px 16px;
    border-left: 4px solid var(--primary);
    border-bottom: 1px solid var(--border);
    text-decoration: none;
    color: var(--text);
    transition: background 0.15s;
  }
  .toc-entry:last-child { border-bottom: none; }
  .toc-entry:hover { background: #f0f4ff; }
  .toc-number {
    font-weight: 700;
    color: var(--primary);
    margin-right: 10px;
    font-size: 0.95em;
    min-width: 24px;
  }
  .toc-icon { margin-right: 8px; font-size: 1.1em; }
  .toc-name { font-weight: 600; margin-right: 6px; }
  .toc-type { color: var(--text-light); font-size: 0.85em; margin-right: 12px; }
  .toc-badges { display: flex; gap: 6px; margin-left: auto; flex-shrink: 0; }
  .toc-badge {
    background: #e9ecef;
    border-radius: 10px;
    padding: 2px 8px;
    font-size: 0.75em;
    font-weight: 600;
    color: var(--text);
    white-space: nowrap;
  }
  .jump-top { text-align: right; margin: 10px 0; font-size: 0.85em; }
  .jump-top a { color: var(--primary); text-decoration: none; }
  .jump-top a:hover { text-decoration: underline; }
  .divider { border-top: 2px solid var(--border); margin: 30px 0; }
  .rbac-group { margin-bottom: 16px; }
  .rbac-group-header {
    font-weight: 600;
    font-size: 0.95em;
    padding: 8px 0 4px;
    color: var(--primary);
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
  }
  .rbac-group-count { font-weight: 400; color: var(--text-light); font-size: 0.85em; }
  .rbac-role-entry {
    margin: 4px 0 8px 16px;
  }
  .rbac-role-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
    font-weight: 500;
  }
  .role-name { white-space: nowrap; font-weight: 500; }
  .rbac-resource-list {
    list-style: none;
    padding: 0;
    margin: 2px 0 4px 24px;
    font-size: 0.88em;
    color: var(--text-light);
  }
  .rbac-resource-list li {
    padding: 1px 0;
  }
  .rbac-resource-list li::before {
    content: '\2022';
    margin-right: 6px;
    color: var(--primary);
  }
  .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .stats-bar {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 20px;
  }
  .stat-card {
    flex: 1;
    min-width: 140px;
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
  }
  .stat-value {
    font-size: 2em;
    font-weight: 700;
    color: var(--primary);
    line-height: 1;
  }
  .stat-label {
    font-size: 0.82em;
    color: var(--text-light);
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .report-footer {
    text-align: center;
    padding: 20px 0;
    margin-top: 30px;
    border-top: 1px solid var(--border);
    color: var(--text-light);
    font-size: 0.82em;
  }
  @media print {
    body { background: #fff; padding: 0; }
    .container { max-width: 100%; }
    details { break-inside: avoid; }
    details[open] > summary { page-break-after: avoid; }
    .identity-header { background: var(--primary) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    th { background: var(--primary) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    tr:nth-child(even) td { background: #f8f9fa !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .warnings { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>`

const htmlSingleTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure RBAC Inventory – {{.Report.Identity.DisplayName}}</title>
` + htmlStyle + `
</head>
<body>
<div class="container">
  <h1>Azure RBAC Inventory Report</h1>
  <p class="subtitle">Generated {{.Generated}}</p>

  <div class="identity-header">
    <h2>{{.Report.Identity.DisplayName}}</h2>
    <div class="identity-meta">
      <div class="meta-item"><span class="meta-label">Object ID</span><span class="meta-value mono">{{.Report.Identity.ObjectID}}</span></div>
      <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{{.Report.Identity.Type}}</span></div>
      {{if .Report.Identity.AppID}}<div class="meta-item"><span class="meta-label">App ID</span><span class="meta-value mono">{{.Report.Identity.AppID}}</span></div>{{end}}
      {{if .Report.Identity.ServicePrincipalType}}<div class="meta-item"><span class="meta-label">SPN Type</span><span class="meta-value">{{.Report.Identity.ServicePrincipalType}}</span></div>{{end}}
      <div class="meta-item"><span class="meta-label">Cloud</span><span class="meta-value">{{.Report.Cloud}}</span></div>
      {{if .Report.Identity.IsMerged}}<div class="meta-item"><span class="meta-label">Status</span><span class="meta-value"><span class="badge badge-delivered">Merged: App + SPN</span></span></div>{{end}}
    </div>
  </div>

  {{if .Report.Warnings}}
  <div class="warnings">
    <h3>⚠ Warnings ({{len .Report.Warnings}})</h3>
    <ul>{{range .Report.Warnings}}<li>{{.}}</li>{{end}}</ul>
  </div>
  {{end}}

  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-value">{{len .Report.RBACAssignments}}</div>
      <div class="stat-label">RBAC Roles</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len .Report.DirectoryRoles}}</div>
      <div class="stat-label">Directory Roles</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len .Report.AccessPackages}}</div>
      <div class="stat-label">Access Packages</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len .Report.GroupMemberships}}</div>
      <div class="stat-label">Groups</div>
    </div>
  </div>

  <details open>
    <summary>Azure RBAC Assignments <span class="section-count">{{len .Report.RBACAssignments}}</span></summary>
    <div class="section-body">
    {{if .RBACGroups}}
      {{range .RBACGroups}}
      <div class="rbac-group">
        <div class="rbac-group-header">► {{.Name}} <span class="rbac-group-count">({{.TotalItems}})</span></div>
        {{range .RoleGroups}}
        <div class="rbac-role-entry">
          <div class="rbac-role-header">
            <span class="role-name">{{.RoleName}}</span>
            {{if eq .AssignmentType "Direct"}}<span class="badge badge-direct">Direct</span>
            {{else}}<span class="badge badge-inherited">{{.AssignmentType}}</span>{{end}}
          </div>
          {{if .Resources}}
          <ul class="rbac-resource-list">
            {{range .Resources}}
            <li>{{.}}</li>
            {{end}}
          </ul>
          {{end}}
        </div>
        {{end}}
      </div>
      {{end}}
    {{else}}<p class="empty-msg">No RBAC assignments found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Entra ID Directory Roles <span class="section-count">{{len .Report.DirectoryRoles}}</span></summary>
    <div class="section-body">
    {{if .Report.DirectoryRoles}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Role Name</th><th>Role ID</th><th>Status</th></tr></thead>
        <tbody>
        {{range .Report.DirectoryRoles}}
        <tr>
          <td>{{.RoleName}}</td>
          <td>{{.RoleID}}</td>
          <td>{{if eq .Status "Active"}}<span class="badge badge-active">Active</span>{{else}}<span class="badge badge-default">{{.Status}}</span>{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No directory roles found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Access Package Assignments <span class="section-count">{{len .Report.AccessPackages}}</span></summary>
    <div class="section-body">
    {{if .Report.AccessPackages}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Package Name</th><th>Catalog</th><th>Status</th><th>Expiration</th></tr></thead>
        <tbody>
        {{range .Report.AccessPackages}}
        <tr>
          <td>{{.PackageName}}</td>
          <td>{{.CatalogName}}</td>
          <td>{{if eq .Status "Delivered"}}<span class="badge badge-delivered">Delivered</span>{{else if eq .Status "Expired"}}<span class="badge badge-expired">Expired</span>{{else if eq .Status "Pending Approval"}}<span class="badge badge-pending">Pending</span>{{else}}<span class="badge badge-default">{{.Status}}</span>{{end}}</td>
          <td>{{.ExpirationDate}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No access package assignments found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Access Package Requests <span class="section-count">{{len .Report.AccessRequests}}</span></summary>
    <div class="section-body">
    {{if .Report.AccessRequests}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Package Name</th><th>Request Type</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
        {{range .Report.AccessRequests}}
        <tr>
          <td>{{.PackageName}}</td>
          <td>{{.RequestType}}</td>
          <td><span class="badge badge-default">{{.Status}}</span></td>
          <td>{{.CreatedDate}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No access package requests found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Group Memberships <span class="section-count">{{len .Report.GroupMemberships}}</span></summary>
    <div class="section-body">
    {{if .Report.GroupMemberships}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Group Name</th><th>Group Type</th><th>Membership</th></tr></thead>
        <tbody>
        {{range .Report.GroupMemberships}}
        <tr>
          <td>{{.GroupName}}</td>
          <td>{{.GroupType}}</td>
          <td>{{if eq .Membership "Direct"}}<span class="badge badge-direct">Direct</span>{{else}}<span class="badge badge-transitive">Transitive</span>{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No group memberships found.</p>{{end}}
    </div>
  </details>

  <div class="report-footer">
    Generated by Azure RBAC Inventory · {{.Generated}}
  </div>

</div>
</body>
</html>`

const htmlMultiTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure RBAC Inventory – Multiple Identities</title>
` + htmlStyle + `
</head>
<body>
<div class="container">
  <h1>Azure RBAC Inventory Report – Multiple Identities</h1>
  <p class="subtitle">Generated {{.Generated}} · {{len .Identities}} identities</p>

  <div id="toc" class="card toc">
    <h3>Table of Contents</h3>
    <div class="toc-list">
    {{range $i, $id := .Identities}}
    <a class="toc-entry" href="#identity-{{$i}}">
      <span class="toc-number">{{add $i 1}}.</span>
      <span class="toc-icon">{{if eq (printf "%s" $id.Report.Identity.Type) "ServicePrincipal"}}🔑{{else if eq (printf "%s" $id.Report.Identity.Type) "User"}}👤{{else if eq (printf "%s" $id.Report.Identity.Type) "Group"}}👥{{else if eq (printf "%s" $id.Report.Identity.Type) "ManagedIdentity"}}🤖{{else if eq (printf "%s" $id.Report.Identity.Type) "Application"}}📱{{else}}🔷{{end}}</span>
      <span class="toc-name">{{$id.Report.Identity.DisplayName}}</span>
      <span class="toc-type">({{$id.Report.Identity.Type}})</span>
      <span class="toc-badges">
        <span class="toc-badge">RBAC: {{len $id.Report.RBACAssignments}}</span>
        <span class="toc-badge">Roles: {{len $id.Report.DirectoryRoles}}</span>
        <span class="toc-badge">Groups: {{len $id.Report.GroupMemberships}}</span>
      </span>
    </a>
    {{end}}
    </div>
  </div>

  {{range $i, $id := .Identities}}
  {{if $i}}<div class="divider"></div>{{end}}

  <div id="identity-{{$i}}" class="identity-header">
    <h2>{{$id.Report.Identity.DisplayName}}</h2>
    <div class="identity-meta">
      <div class="meta-item"><span class="meta-label">Object ID</span><span class="meta-value mono">{{$id.Report.Identity.ObjectID}}</span></div>
      <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{{$id.Report.Identity.Type}}</span></div>
      {{if $id.Report.Identity.AppID}}<div class="meta-item"><span class="meta-label">App ID</span><span class="meta-value mono">{{$id.Report.Identity.AppID}}</span></div>{{end}}
      {{if $id.Report.Identity.ServicePrincipalType}}<div class="meta-item"><span class="meta-label">SPN Type</span><span class="meta-value">{{$id.Report.Identity.ServicePrincipalType}}</span></div>{{end}}
      <div class="meta-item"><span class="meta-label">Cloud</span><span class="meta-value">{{$id.Report.Cloud}}</span></div>
      {{if $id.Report.Identity.IsMerged}}<div class="meta-item"><span class="meta-label">Status</span><span class="meta-value"><span class="badge badge-delivered">Merged: App + SPN</span></span></div>{{end}}
    </div>
  </div>

  {{if $id.Report.Warnings}}
  <div class="warnings">
    <h3>⚠ Warnings ({{len $id.Report.Warnings}})</h3>
    <ul>{{range $id.Report.Warnings}}<li>{{.}}</li>{{end}}</ul>
  </div>
  {{end}}

  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-value">{{len $id.Report.RBACAssignments}}</div>
      <div class="stat-label">RBAC Roles</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len $id.Report.DirectoryRoles}}</div>
      <div class="stat-label">Directory Roles</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len $id.Report.AccessPackages}}</div>
      <div class="stat-label">Access Packages</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len $id.Report.GroupMemberships}}</div>
      <div class="stat-label">Groups</div>
    </div>
  </div>

  <details open>
    <summary>Azure RBAC Assignments <span class="section-count">{{len $id.Report.RBACAssignments}}</span></summary>
    <div class="section-body">
    {{if $id.RBACGroups}}
      {{range $id.RBACGroups}}
      <div class="rbac-group">
        <div class="rbac-group-header">► {{.Name}} <span class="rbac-group-count">({{.TotalItems}})</span></div>
        {{range .RoleGroups}}
        <div class="rbac-role-entry">
          <div class="rbac-role-header">
            <span class="role-name">{{.RoleName}}</span>
            {{if eq .AssignmentType "Direct"}}<span class="badge badge-direct">Direct</span>
            {{else}}<span class="badge badge-inherited">{{.AssignmentType}}</span>{{end}}
          </div>
          {{if .Resources}}
          <ul class="rbac-resource-list">
            {{range .Resources}}
            <li>{{.}}</li>
            {{end}}
          </ul>
          {{end}}
        </div>
        {{end}}
      </div>
      {{end}}
    {{else}}<p class="empty-msg">No RBAC assignments found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Entra ID Directory Roles <span class="section-count">{{len $id.Report.DirectoryRoles}}</span></summary>
    <div class="section-body">
    {{if $id.Report.DirectoryRoles}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Role Name</th><th>Role ID</th><th>Status</th></tr></thead>
        <tbody>
        {{range $id.Report.DirectoryRoles}}
        <tr>
          <td>{{.RoleName}}</td>
          <td>{{.RoleID}}</td>
          <td>{{if eq .Status "Active"}}<span class="badge badge-active">Active</span>{{else}}<span class="badge badge-default">{{.Status}}</span>{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No directory roles found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Access Package Assignments <span class="section-count">{{len $id.Report.AccessPackages}}</span></summary>
    <div class="section-body">
    {{if $id.Report.AccessPackages}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Package Name</th><th>Catalog</th><th>Status</th><th>Expiration</th></tr></thead>
        <tbody>
        {{range $id.Report.AccessPackages}}
        <tr>
          <td>{{.PackageName}}</td>
          <td>{{.CatalogName}}</td>
          <td>{{if eq .Status "Delivered"}}<span class="badge badge-delivered">Delivered</span>{{else if eq .Status "Expired"}}<span class="badge badge-expired">Expired</span>{{else if eq .Status "Pending Approval"}}<span class="badge badge-pending">Pending</span>{{else}}<span class="badge badge-default">{{.Status}}</span>{{end}}</td>
          <td>{{.ExpirationDate}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No access package assignments found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Access Package Requests <span class="section-count">{{len $id.Report.AccessRequests}}</span></summary>
    <div class="section-body">
    {{if $id.Report.AccessRequests}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Package Name</th><th>Request Type</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
        {{range $id.Report.AccessRequests}}
        <tr>
          <td>{{.PackageName}}</td>
          <td>{{.RequestType}}</td>
          <td><span class="badge badge-default">{{.Status}}</span></td>
          <td>{{.CreatedDate}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No access package requests found.</p>{{end}}
    </div>
  </details>

  <details>
    <summary>Group Memberships <span class="section-count">{{len $id.Report.GroupMemberships}}</span></summary>
    <div class="section-body">
    {{if $id.Report.GroupMemberships}}
      <div class="table-wrap">
      <table>
        <thead><tr><th>Group Name</th><th>Group Type</th><th>Membership</th></tr></thead>
        <tbody>
        {{range $id.Report.GroupMemberships}}
        <tr>
          <td>{{.GroupName}}</td>
          <td>{{.GroupType}}</td>
          <td>{{if eq .Membership "Direct"}}<span class="badge badge-direct">Direct</span>{{else}}<span class="badge badge-transitive">Transitive</span>{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      </div>
    {{else}}<p class="empty-msg">No group memberships found.</p>{{end}}
    </div>
  </details>

  <div class="jump-top"><a href="#toc">↑ Back to Table of Contents</a></div>

  {{end}}

  <div class="report-footer">
    Generated by Azure RBAC Inventory · {{.Generated}}
  </div>

</div>
</body>
</html>`
