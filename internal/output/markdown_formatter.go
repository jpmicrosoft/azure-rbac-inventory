package output

import (
	"bytes"
	"fmt"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// MarkdownFormatter implements the Formatter interface for Markdown output.
type MarkdownFormatter struct{}

// FormatReport formats a single identity report as GitHub-flavored Markdown.
func (f *MarkdownFormatter) FormatReport(rpt *report.Report) ([]byte, error) {
	var buf bytes.Buffer
	writeMarkdownReport(&buf, rpt)
	return buf.Bytes(), nil
}

// FormatMultiReport formats multiple identity reports as Markdown,
// separated by horizontal rules.
func (f *MarkdownFormatter) FormatMultiReport(reports []*report.Report) ([]byte, error) {
	var buf bytes.Buffer
	for i, rpt := range reports {
		if i > 0 {
			buf.WriteString("\n---\n\n")
		}
		writeMarkdownReport(&buf, rpt)
	}
	return buf.Bytes(), nil
}

// FileExtension returns ".md".
func (f *MarkdownFormatter) FileExtension() string {
	return ".md"
}

// writeMarkdownReport writes a single report in Markdown format.
func writeMarkdownReport(buf *bytes.Buffer, rpt *report.Report) {
	fmt.Fprintf(buf, "## Identity Report: %s\n\n", rpt.Identity.DisplayName)

	fmt.Fprintf(buf, "- **Object ID:** %s\n", rpt.Identity.ObjectID)
	fmt.Fprintf(buf, "- **Type:** %s\n", string(rpt.Identity.Type))
	if rpt.Identity.AppID != "" {
		fmt.Fprintf(buf, "- **App ID:** %s\n", rpt.Identity.AppID)
	}
	if rpt.Identity.ServicePrincipalType != "" {
		fmt.Fprintf(buf, "- **SPN Type:** %s\n", rpt.Identity.ServicePrincipalType)
	}
	fmt.Fprintf(buf, "- **Cloud:** %s\n", rpt.Cloud)
	buf.WriteString("\n")

	// RBAC Assignments
	fmt.Fprintf(buf, "### Azure Role Assignments (%d)\n\n", len(rpt.RBACAssignments))
	if len(rpt.RBACAssignments) == 0 {
		buf.WriteString("_No results found._\n\n")
	} else {
		buf.WriteString("| Role | Scope | Scope Type | Assignment Type |\n")
		buf.WriteString("|------|-------|------------|-----------------|\n")
		for _, a := range rpt.RBACAssignments {
			fmt.Fprintf(buf, "| %s | %s | %s | %s |\n",
				escapeMarkdown(a.RoleName),
				escapeMarkdown(a.Scope),
				escapeMarkdown(a.ScopeType),
				escapeMarkdown(a.AssignmentType))
		}
		buf.WriteString("\n")
	}

	// Directory Roles
	fmt.Fprintf(buf, "### Entra ID Directory Roles (%d)\n\n", len(rpt.DirectoryRoles))
	if len(rpt.DirectoryRoles) == 0 {
		buf.WriteString("_No results found._\n\n")
	} else {
		buf.WriteString("| Role | Role ID | Status |\n")
		buf.WriteString("|------|---------|--------|\n")
		for _, r := range rpt.DirectoryRoles {
			fmt.Fprintf(buf, "| %s | %s | %s |\n",
				escapeMarkdown(r.RoleName),
				escapeMarkdown(r.RoleID),
				escapeMarkdown(r.Status))
		}
		buf.WriteString("\n")
	}

	// Access Package Assignments
	fmt.Fprintf(buf, "### Access Package Assignments (%d)\n\n", len(rpt.AccessPackages))
	if rpt.SkippedAccessPackages {
		buf.WriteString("_Skipped (use --include-access-packages to query)_\n\n")
	} else if len(rpt.AccessPackages) == 0 {
		buf.WriteString("_No results found._\n\n")
	} else {
		buf.WriteString("| Package | Catalog | Status | Expires |\n")
		buf.WriteString("|---------|---------|--------|---------|\n")
		for _, p := range rpt.AccessPackages {
			expires := p.ExpirationDate
			if expires == "" {
				expires = "-"
			}
			fmt.Fprintf(buf, "| %s | %s | %s | %s |\n",
				escapeMarkdown(p.PackageName),
				escapeMarkdown(p.CatalogName),
				escapeMarkdown(p.Status),
				escapeMarkdown(expires))
		}
		buf.WriteString("\n")
	}

	// Access Package Requests
	fmt.Fprintf(buf, "### Access Package Requests (%d)\n\n", len(rpt.AccessRequests))
	if rpt.SkippedAccessPackages {
		buf.WriteString("_Skipped (use --include-access-packages to query)_\n\n")
	} else if len(rpt.AccessRequests) == 0 {
		buf.WriteString("_No results found._\n\n")
	} else {
		buf.WriteString("| Package | Type | Status | Created |\n")
		buf.WriteString("|---------|------|--------|---------|\n")
		for _, r := range rpt.AccessRequests {
			fmt.Fprintf(buf, "| %s | %s | %s | %s |\n",
				escapeMarkdown(r.PackageName),
				escapeMarkdown(r.RequestType),
				escapeMarkdown(r.Status),
				escapeMarkdown(r.CreatedDate))
		}
		buf.WriteString("\n")
	}

	// Group Memberships
	fmt.Fprintf(buf, "### Group Memberships (%d)\n\n", len(rpt.GroupMemberships))
	if len(rpt.GroupMemberships) == 0 {
		buf.WriteString("_No results found._\n\n")
	} else {
		buf.WriteString("| Group | Type | Membership |\n")
		buf.WriteString("|-------|------|------------|\n")
		for _, g := range rpt.GroupMemberships {
			fmt.Fprintf(buf, "| %s | %s | %s |\n",
				escapeMarkdown(g.GroupName),
				escapeMarkdown(g.GroupType),
				escapeMarkdown(g.Membership))
		}
		buf.WriteString("\n")
	}

	// Warnings
	if len(rpt.Warnings) > 0 {
		fmt.Fprintf(buf, "### Warnings (%d)\n\n", len(rpt.Warnings))
		for _, w := range rpt.Warnings {
			fmt.Fprintf(buf, "- ⚠️ %s\n", w)
		}
		buf.WriteString("\n")
	}
}

// escapeMarkdown escapes pipe characters in Markdown table cells.
func escapeMarkdown(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if r == '|' {
			buf.WriteString("\\|")
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}
