package output

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/compare"
)

type compareHTMLData struct {
	Result    *compare.ComparisonResult
	Generated string
}

type modelCompareHTMLData struct {
	Result    *compare.ModelComparisonResult
	Generated string
}

const compareCSS = `
<style>
  .diff-section { margin-bottom: 16px; padding: 12px 16px; border-radius: 6px; }
  .diff-removed { background: #fff5f5; border-left: 4px solid #dc3545; }
  .diff-added { background: #f0fff0; border-left: 4px solid #28a745; }
  .diff-shared { background: #f8f9fa; border-left: 4px solid #6c757d; }
  .diff-inferred { background: #fffbf0; border-left: 4px solid #f0ad4e; }
  .diff-section h4 { margin-bottom: 8px; font-size: 0.95em; }
  .diff-section ul { list-style: none; padding: 0; margin: 0; }
  .diff-section li { padding: 3px 0; font-size: 0.9em; }
  .diff-marker { font-weight: 700; margin-right: 6px; }
  .diff-marker.removed { color: #dc3545; }
  .diff-marker.added { color: #28a745; }
  .diff-marker.shared { color: #6c757d; }
  .diff-marker.inferred { color: #f0ad4e; }
  .diff-scope { color: var(--text-light); font-size: 0.85em; }
  .inferred-pair { margin-left: 24px; font-size: 0.82em; color: var(--text-light); font-family: monospace; }
  .inferred-pair mark { background: #fff3cd; padding: 1px 3px; border-radius: 3px; color: #856404; }
  .match-bar { height: 8px; border-radius: 4px; background: #e9ecef; overflow: hidden; margin: 8px 0; }
  .match-fill { height: 100%; border-radius: 4px; background: var(--primary); }
</style>`

const compareHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure RBAC Inventory – Comparison</title>
` + htmlStyle + `
` + compareCSS + `
</head>
<body>
<div class="container">
  <h1>Azure RBAC Inventory – Comparison Report</h1>
  <p class="subtitle">Generated {{.Generated}}</p>

  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-value">{{printf "%.0f" .Result.MatchPercent}}%</div>
      <div class="stat-label">Match</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len .Result.RBAC.OnlyA | add (len .Result.DirectoryRoles.OnlyA) | add (len .Result.Groups.OnlyA) | add (len .Result.AccessPackages.OnlyA)}}</div>
      <div class="stat-label">Only in A</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len .Result.RBAC.OnlyB | add (len .Result.DirectoryRoles.OnlyB) | add (len .Result.Groups.OnlyB) | add (len .Result.AccessPackages.OnlyB)}}</div>
      <div class="stat-label">Only in B</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{len .Result.RBAC.Shared | add (len .Result.DirectoryRoles.Shared) | add (len .Result.Groups.Shared) | add (len .Result.AccessPackages.Shared)}}</div>
      <div class="stat-label">Shared</div>
    </div>
    {{if .Result.RBAC.Inferred}}
    <div class="stat-card">
      <div class="stat-value" style="color: #f0ad4e;">{{len .Result.RBAC.Inferred}}</div>
      <div class="stat-label">Inferred</div>
    </div>
    {{end}}
  </div>

  <div style="display: flex; gap: 20px; margin-bottom: 20px;">
    <div class="identity-header" style="flex: 1;">
      <h2>Identity A</h2>
      <div class="identity-meta">
        <div class="meta-item"><span class="meta-label">Name</span><span class="meta-value">{{.Result.IdentityA.DisplayName}}</span></div>
        <div class="meta-item"><span class="meta-label">Object ID</span><span class="meta-value mono">{{.Result.IdentityA.ObjectID}}</span></div>
        <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{{.Result.IdentityA.Type}}</span></div>
      </div>
    </div>
    <div class="identity-header" style="flex: 1;">
      <h2>Identity B</h2>
      <div class="identity-meta">
        <div class="meta-item"><span class="meta-label">Name</span><span class="meta-value">{{.Result.IdentityB.DisplayName}}</span></div>
        <div class="meta-item"><span class="meta-label">Object ID</span><span class="meta-value mono">{{.Result.IdentityB.ObjectID}}</span></div>
        <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{{.Result.IdentityB.Type}}</span></div>
      </div>
    </div>
  </div>

  {{$nameA := .Result.IdentityA.DisplayName}}
  {{$nameB := .Result.IdentityB.DisplayName}}

  {{$rbacTotal := len .Result.RBAC.OnlyA | add (len .Result.RBAC.OnlyB) | add (len .Result.RBAC.Shared) | add (len .Result.RBAC.Inferred)}}
  {{if gt $rbacTotal 0}}
  <details open>
    <summary>RBAC Differences <span class="section-count">{{$rbacTotal}}</span></summary>
    <div class="section-body">
      {{if .Result.RBAC.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Only in {{$nameA}} ({{len .Result.RBAC.OnlyA}})</h4>
        <ul>
          {{range .Result.RBAC.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.RoleName}} <span class="diff-scope">({{.ScopeType}})</span> <span class="diff-scope mono" style="font-size: 0.8em;">{{.Scope}}</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.RBAC.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Only in {{$nameB}} ({{len .Result.RBAC.OnlyB}})</h4>
        <ul>
          {{range .Result.RBAC.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.RoleName}} <span class="diff-scope">({{.ScopeType}})</span> <span class="diff-scope mono" style="font-size: 0.8em;">{{.Scope}}</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.RBAC.Shared}}
      <div class="diff-section diff-shared">
        <h4>Shared ({{len .Result.RBAC.Shared}})</h4>
        <ul>
          {{range .Result.RBAC.Shared}}
          <li><span class="diff-marker shared">✓</span> {{.RoleName}} <span class="diff-scope">({{.ScopeType}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.RBAC.Inferred}}
      <div class="diff-section diff-inferred">
        <h4>Inferred Matches ({{len .Result.RBAC.Inferred}})</h4>
        <p style="font-size: 0.85em; color: #856404; margin: 0 0 8px 0;">Matched by role name and scope type — exact scope could not be verified</p>
        <ul>
          {{range .Result.RBAC.Inferred}}
          <li>
            <span class="diff-marker inferred">≈</span> {{.Model.RoleName}} <span class="diff-scope">({{.Model.ScopeType}})</span>
            <div class="inferred-pair">Model:&nbsp; {{highlightScope .Model.Scope .Target.Scope "model"}}</div>
            <div class="inferred-pair">Target: {{highlightScope .Model.Scope .Target.Scope "target"}}</div>
          </li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
  </details>
  {{end}}

  {{$rolesTotal := len .Result.DirectoryRoles.OnlyA | add (len .Result.DirectoryRoles.OnlyB) | add (len .Result.DirectoryRoles.Shared)}}
  {{if gt $rolesTotal 0}}
  <details>
    <summary>Directory Roles Differences <span class="section-count">{{$rolesTotal}}</span></summary>
    <div class="section-body">
      {{if .Result.DirectoryRoles.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Only in {{$nameA}} ({{len .Result.DirectoryRoles.OnlyA}})</h4>
        <ul>
          {{range .Result.DirectoryRoles.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.RoleName}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.DirectoryRoles.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Only in {{$nameB}} ({{len .Result.DirectoryRoles.OnlyB}})</h4>
        <ul>
          {{range .Result.DirectoryRoles.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.RoleName}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.DirectoryRoles.Shared}}
      <div class="diff-section diff-shared">
        <h4>Shared ({{len .Result.DirectoryRoles.Shared}})</h4>
        <ul>
          {{range .Result.DirectoryRoles.Shared}}
          <li><span class="diff-marker shared">✓</span> {{.RoleName}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
  </details>
  {{end}}

  {{$groupsTotal := len .Result.Groups.OnlyA | add (len .Result.Groups.OnlyB) | add (len .Result.Groups.Shared)}}
  {{if gt $groupsTotal 0}}
  <details>
    <summary>Groups Differences <span class="section-count">{{$groupsTotal}}</span></summary>
    <div class="section-body">
      {{if .Result.Groups.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Only in {{$nameA}} ({{len .Result.Groups.OnlyA}})</h4>
        <ul>
          {{range .Result.Groups.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.GroupName}} <span class="diff-scope">({{.GroupType}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.Groups.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Only in {{$nameB}} ({{len .Result.Groups.OnlyB}})</h4>
        <ul>
          {{range .Result.Groups.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.GroupName}} <span class="diff-scope">({{.GroupType}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.Groups.Shared}}
      <div class="diff-section diff-shared">
        <h4>Shared ({{len .Result.Groups.Shared}})</h4>
        <ul>
          {{range .Result.Groups.Shared}}
          <li><span class="diff-marker shared">✓</span> {{.GroupName}} <span class="diff-scope">({{.GroupType}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
  </details>
  {{end}}

  {{$pkgsTotal := len .Result.AccessPackages.OnlyA | add (len .Result.AccessPackages.OnlyB) | add (len .Result.AccessPackages.Shared)}}
  {{if gt $pkgsTotal 0}}
  <details>
    <summary>Access Packages Differences <span class="section-count">{{$pkgsTotal}}</span></summary>
    <div class="section-body">
      {{if .Result.AccessPackages.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Only in {{$nameA}} ({{len .Result.AccessPackages.OnlyA}})</h4>
        <ul>
          {{range .Result.AccessPackages.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.PackageName}} <span class="diff-scope">({{.CatalogName}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.AccessPackages.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Only in {{$nameB}} ({{len .Result.AccessPackages.OnlyB}})</h4>
        <ul>
          {{range .Result.AccessPackages.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.PackageName}} <span class="diff-scope">({{.CatalogName}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Result.AccessPackages.Shared}}
      <div class="diff-section diff-shared">
        <h4>Shared ({{len .Result.AccessPackages.Shared}})</h4>
        <ul>
          {{range .Result.AccessPackages.Shared}}
          <li><span class="diff-marker shared">✓</span> {{.PackageName}} <span class="diff-scope">({{.CatalogName}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
    </div>
  </details>
  {{end}}

  <div class="report-footer">Generated by Azure RBAC Inventory · {{.Generated}}</div>
</div>
</body>
</html>`

const modelCompareHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure RBAC Inventory – Model Comparison</title>
` + htmlStyle + `
` + compareCSS + `
</head>
<body>
<div class="container">
  <h1>Azure RBAC Inventory – Model Comparison Report</h1>
  <p class="subtitle">Generated {{.Generated}}</p>

  <div class="identity-header">
    <h2>Model Identity</h2>
    <div class="identity-meta">
      <div class="meta-item"><span class="meta-label">Name</span><span class="meta-value">{{.Result.Model.DisplayName}}</span></div>
      <div class="meta-item"><span class="meta-label">Object ID</span><span class="meta-value mono">{{.Result.Model.ObjectID}}</span></div>
      <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{{.Result.Model.Type}}</span></div>
      {{if .Result.GoldenWorkload}}
      <div class="meta-item"><span class="meta-label">Workload</span><span class="meta-value">{{.Result.GoldenWorkload}}</span></div>
      {{end}}
    </div>
  </div>

  {{if .Result.ModelRBAC}}
  <details>
    <summary>Model RBAC Assignments <span class="section-count">{{len .Result.ModelRBAC}}</span></summary>
    <div class="section-body">
      <div class="table-wrap">
      <table>
        <thead><tr><th>Role</th><th>Scope Type</th><th>Scope</th></tr></thead>
        <tbody>
          {{range .Result.ModelRBAC}}
          <tr><td>{{.RoleName}}</td><td>{{.ScopeType}}</td><td class="mono" style="font-size: 0.8em;">{{.Scope}}</td></tr>
          {{end}}
        </tbody>
      </table>
      </div>
    </div>
  </details>
  {{end}}

  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-value">{{len .Result.Results}}</div>
      <div class="stat-label">Targets</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{countFullMatch .Result.Results}}</div>
      <div class="stat-label">100% Match</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{countDrift .Result.Results}}</div>
      <div class="stat-label">With Drift</div>
    </div>
  </div>

  <details open>
    <summary>Target Summary <span class="section-count">{{len .Result.Results}}</span></summary>
    <div class="section-body">
      <input type="text" id="target-search" placeholder="Search targets by name, type, or workload…"
        style="width: 100%; padding: 8px 12px; margin-bottom: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9em; box-sizing: border-box;"
        oninput="(function(v){var rows=document.querySelectorAll('#target-table tbody tr');v=v.toLowerCase();rows.forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(v)!==-1?'':'none'})})(this.value)">
      <div class="table-wrap">
      <table id="target-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Type</th>
            <th>Workload</th>
            <th>Match</th>
            <th>Missing RBAC</th>
            <th>Extra RBAC</th>
            <th>Missing Roles</th>
            <th>Extra Roles</th>
            <th>Missing Groups</th>
            <th>Extra Groups</th>
          </tr>
        </thead>
        <tbody>
          {{range .Result.Results}}
          <tr>
            <td>{{if lt .MatchPercent 100.0}}<a href="#target-{{.Target.ObjectID}}" style="color: var(--primary); text-decoration: none; font-weight: 500;">{{.Target.DisplayName}}</a>{{else}}{{.Target.DisplayName}}{{end}}</td>
            <td>{{.Target.Type}}</td>
            <td>{{if .WorkloadName}}{{.WorkloadName}}{{else}}-{{end}}</td>
            <td>
              {{printf "%.0f" .MatchPercent}}%
              <div class="match-bar"><div class="match-fill" style="width: {{printf "%.0f" .MatchPercent}}%"></div></div>
            </td>
            <td>{{.MissingRBAC}}</td>
            <td>{{.ExtraRBAC}}</td>
            <td>{{.MissingRoles}}</td>
            <td>{{.ExtraRoles}}</td>
            <td>{{.MissingGroups}}</td>
            <td>{{.ExtraGroups}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      </div>
    </div>
  </details>

  {{range .Result.Results}}
  {{if lt .MatchPercent 100.0}}
  <details id="target-{{.Target.ObjectID}}">
    {{if .WorkloadName}}
    <summary>{{.Target.DisplayName}} ({{.WorkloadName}}) – {{printf "%.0f" .MatchPercent}}% Match <span class="section-count">drift</span></summary>
    {{else}}
    <summary>{{.Target.DisplayName}} – {{printf "%.0f" .MatchPercent}}% Match <span class="section-count">drift</span></summary>
    {{end}}
    <div class="section-body">
      {{$nameA := $.Result.Model.DisplayName}}
      {{$nameB := .Target.DisplayName}}

      {{$rbacTotal := len .Comparison.RBAC.OnlyA | add (len .Comparison.RBAC.OnlyB)}}
      {{if gt $rbacTotal 0}}
      <h3 style="margin-bottom: 12px; font-size: 1em; color: var(--primary);">RBAC Differences</h3>
      {{if .Comparison.RBAC.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Missing from {{$nameB}} ({{len .Comparison.RBAC.OnlyA}})</h4>
        <ul>
          {{range .Comparison.RBAC.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.RoleName}} <span class="diff-scope">({{.ScopeType}})</span> <span class="diff-scope mono" style="font-size: 0.8em;">{{.Scope}}</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Comparison.RBAC.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Extra in {{$nameB}} ({{len .Comparison.RBAC.OnlyB}})</h4>
        <ul>
          {{range .Comparison.RBAC.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.RoleName}} <span class="diff-scope">({{.ScopeType}})</span> <span class="diff-scope mono" style="font-size: 0.8em;">{{.Scope}}</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{end}}

      {{if .Comparison.RBAC.Inferred}}
      <h3 style="margin-bottom: 12px; font-size: 1em; color: #f0ad4e;">Inferred Matches</h3>
      <div class="diff-section diff-inferred">
        <h4>Matched by role name and scope type ({{len .Comparison.RBAC.Inferred}})</h4>
        <p style="font-size: 0.85em; color: #856404; margin: 0 0 8px 0;">Exact scope could not be verified — matched structurally</p>
        <ul>
          {{range .Comparison.RBAC.Inferred}}
          <li>
            <span class="diff-marker inferred">≈</span> {{.Model.RoleName}} <span class="diff-scope">({{.Model.ScopeType}})</span>
            <div class="inferred-pair">Model:&nbsp; {{highlightScope .Model.Scope .Target.Scope "model"}}</div>
            <div class="inferred-pair">Target: {{highlightScope .Model.Scope .Target.Scope "target"}}</div>
          </li>
          {{end}}
        </ul>
      </div>
      {{end}}

      {{$rolesTotal:= len .Comparison.DirectoryRoles.OnlyA | add (len .Comparison.DirectoryRoles.OnlyB)}}
      {{if gt $rolesTotal 0}}
      <h3 style="margin-bottom: 12px; font-size: 1em; color: var(--primary);">Directory Roles Differences</h3>
      {{if .Comparison.DirectoryRoles.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Missing from {{$nameB}} ({{len .Comparison.DirectoryRoles.OnlyA}})</h4>
        <ul>
          {{range .Comparison.DirectoryRoles.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.RoleName}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Comparison.DirectoryRoles.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Extra in {{$nameB}} ({{len .Comparison.DirectoryRoles.OnlyB}})</h4>
        <ul>
          {{range .Comparison.DirectoryRoles.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.RoleName}}</li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{end}}

      {{$groupsTotal := len .Comparison.Groups.OnlyA | add (len .Comparison.Groups.OnlyB)}}
      {{if gt $groupsTotal 0}}
      <h3 style="margin-bottom: 12px; font-size: 1em; color: var(--primary);">Groups Differences</h3>
      {{if .Comparison.Groups.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Missing from {{$nameB}} ({{len .Comparison.Groups.OnlyA}})</h4>
        <ul>
          {{range .Comparison.Groups.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.GroupName}} <span class="diff-scope">({{.GroupType}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Comparison.Groups.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Extra in {{$nameB}} ({{len .Comparison.Groups.OnlyB}})</h4>
        <ul>
          {{range .Comparison.Groups.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.GroupName}} <span class="diff-scope">({{.GroupType}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{end}}

      {{$pkgsTotal := len .Comparison.AccessPackages.OnlyA | add (len .Comparison.AccessPackages.OnlyB)}}
      {{if gt $pkgsTotal 0}}
      <h3 style="margin-bottom: 12px; font-size: 1em; color: var(--primary);">Access Packages Differences</h3>
      {{if .Comparison.AccessPackages.OnlyA}}
      <div class="diff-section diff-removed">
        <h4>Missing from {{$nameB}} ({{len .Comparison.AccessPackages.OnlyA}})</h4>
        <ul>
          {{range .Comparison.AccessPackages.OnlyA}}
          <li><span class="diff-marker removed">✗</span> {{.PackageName}} <span class="diff-scope">({{.CatalogName}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{if .Comparison.AccessPackages.OnlyB}}
      <div class="diff-section diff-added">
        <h4>Extra in {{$nameB}} ({{len .Comparison.AccessPackages.OnlyB}})</h4>
        <ul>
          {{range .Comparison.AccessPackages.OnlyB}}
          <li><span class="diff-marker added">✚</span> {{.PackageName}} <span class="diff-scope">({{.CatalogName}})</span></li>
          {{end}}
        </ul>
      </div>
      {{end}}
      {{end}}
    </div>
  </details>
  {{end}}
  {{end}}

  <div class="report-footer">Generated by Azure RBAC Inventory · {{.Generated}}</div>
</div>
<script>
(function(){
  function openAndScroll(hash){
    if(!hash)return;
    var el=document.getElementById(hash.slice(1));
    if(!el)return;
    if(el.tagName==='DETAILS'){
      el.open=true;
      el.style.outline='2px solid var(--primary)';
      el.style.borderRadius='8px';
      setTimeout(function(){el.style.outline='';},2500);
    }
    setTimeout(function(){el.scrollIntoView({behavior:'smooth',block:'start'});},50);
  }
  document.querySelectorAll('a[href^="#target-"]').forEach(function(a){
    a.addEventListener('click',function(e){
      e.preventDefault();
      history.replaceState(null,null,a.getAttribute('href'));
      openAndScroll(a.getAttribute('href'));
    });
  });
  if(location.hash)openAndScroll(location.hash);
})();
</script>
</body>
</html>`

// compareFuncMap provides helper functions for comparison templates.
var compareFuncMap = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"countFullMatch": func(results []compare.ModelTargetResult) int {
		n := 0
		for _, r := range results {
			if r.MatchPercent >= 100.0 {
				n++
			}
		}
		return n
	},
	"countDrift": func(results []compare.ModelTargetResult) int {
		n := 0
		for _, r := range results {
			if r.MatchPercent < 100.0 {
				n++
			}
		}
		return n
	},
	// highlightScope renders one side of a scope pair with differing segments
	// wrapped in <mark> tags. side must be "model" or "target".
	"highlightScope": func(modelScope, targetScope, side string) template.HTML {
		mParts := strings.Split(modelScope, "/")
		tParts := strings.Split(targetScope, "/")

		var parts, other []string
		if side == "model" {
			parts = mParts
			other = tParts
		} else {
			parts = tParts
			other = mParts
		}

		out := make([]string, len(parts))
		for i, seg := range parts {
			if i < len(other) && strings.EqualFold(seg, other[i]) {
				out[i] = template.HTMLEscapeString(seg)
			} else {
				out[i] = "<mark>" + template.HTMLEscapeString(seg) + "</mark>"
			}
		}
		return template.HTML(strings.Join(out, "/"))
	},
}

// FormatCompareHTML renders a 1:1 comparison result as standalone HTML.
func FormatCompareHTML(result *compare.ComparisonResult) ([]byte, error) {
	tmpl, err := template.New("compare").Funcs(compareFuncMap).Parse(compareHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing compare HTML template: %w", err)
	}

	data := compareHTMLData{
		Result:    result,
		Generated: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing compare HTML template: %w", err)
	}
	return buf.Bytes(), nil
}

// FormatModelCompareHTML renders a 1:N model comparison result as standalone HTML.
func FormatModelCompareHTML(result *compare.ModelComparisonResult) ([]byte, error) {
	tmpl, err := template.New("modelCompare").Funcs(compareFuncMap).Parse(modelCompareHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing model compare HTML template: %w", err)
	}

	data := modelCompareHTMLData{
		Result:    result,
		Generated: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing model compare HTML template: %w", err)
	}
	return buf.Bytes(), nil
}
