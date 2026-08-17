package output

import (
	"bytes"
	"encoding/csv"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// csvBOM is the UTF-8 byte order mark for proper Excel display.
var csvBOM = []byte{0xEF, 0xBB, 0xBF}

// csvHeader defines the column names for the CSV export.
var csvHeader = []string{
	"Identity", "ObjectID", "IdentityType", "Cloud",
	"Category", "Name", "Scope", "ScopeType",
	"Detail", "Status", "AssignmentType", "ScopeName",
}

var legacyCSVHeader = csvHeader[:len(csvHeader)-1]

// CSVFormatter implements the Formatter interface for CSV output.
type CSVFormatter struct{}

// sanitizeCSVCell prefixes cells that start with formula-trigger characters
// to prevent spreadsheet formula injection when opened in Excel.
func sanitizeCSVCell(s string) string {
	if len(s) > 0 {
		switch s[0] {
		case '=', '+', '-', '@', '\t', '\r':
			return "'" + s
		}
	}
	return s
}

// sanitizeCSVRow applies formula sanitization to all cells in a row.
func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		out[i] = sanitizeCSVCell(cell)
	}
	return out
}

// FormatReport formats a single identity report as CSV.
func (f *CSVFormatter) FormatReport(rpt *report.Report) ([]byte, error) {
	return f.FormatMultiReport([]*report.Report{rpt})
}

// FormatMultiReport formats multiple identity reports as CSV with all
// identities combined. Identity columns distinguish each report.
func (f *CSVFormatter) FormatMultiReport(reports []*report.Report) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(csvBOM)

	w := csv.NewWriter(&buf)
	legacy := reportsUseLegacyOutput(reports)
	header := csvHeader
	if legacy {
		header = legacyCSVHeader
	}
	if err := w.Write(header); err != nil {
		return nil, err
	}

	for _, rpt := range reports {
		name := rpt.Identity.DisplayName
		objectID := rpt.Identity.ObjectID
		idType := string(rpt.Identity.Type)
		cloud := rpt.Cloud

		for _, a := range rpt.RBACAssignments {
			row := []string{
				name, objectID, idType, cloud,
				"RBAC", a.RoleName, a.Scope, a.ScopeType,
				a.PrincipalType, "", a.AssignmentType,
			}
			if !legacy {
				row = append(row, managementGroupScopeName(a.Scope, a.ScopeType, rpt.ManagementGroupNames))
			}
			if err := w.Write(sanitizeCSVRow(row)); err != nil {
				return nil, err
			}
		}

		for _, r := range rpt.DirectoryRoles {
			row := []string{
				name, objectID, idType, cloud,
				"DirectoryRole", r.RoleName, "", "",
				r.RoleID, r.Status, "",
			}
			if !legacy {
				row = append(row, "")
			}
			if err := w.Write(sanitizeCSVRow(row)); err != nil {
				return nil, err
			}
		}

		for _, p := range rpt.AccessPackages {
			row := []string{
				name, objectID, idType, cloud,
				"AccessPackage", p.PackageName, "", "",
				p.CatalogName, p.Status, p.ExpirationDate,
			}
			if !legacy {
				row = append(row, "")
			}
			if err := w.Write(sanitizeCSVRow(row)); err != nil {
				return nil, err
			}
		}

		for _, r := range rpt.AccessRequests {
			row := []string{
				name, objectID, idType, cloud,
				"AccessPackageRequest", r.PackageName, "", "",
				r.RequestType, r.Status, r.CreatedDate,
			}
			if !legacy {
				row = append(row, "")
			}
			if err := w.Write(sanitizeCSVRow(row)); err != nil {
				return nil, err
			}
		}

		for _, g := range rpt.GroupMemberships {
			row := []string{
				name, objectID, idType, cloud,
				"GroupMembership", g.GroupName, "", "",
				g.GroupType, "", g.Membership,
			}
			if !legacy {
				row = append(row, "")
			}
			if err := w.Write(sanitizeCSVRow(row)); err != nil {
				return nil, err
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func reportsUseLegacyOutput(reports []*report.Report) bool {
	return len(reports) > 0 && reports[0] != nil && reports[0].LegacyOutput
}

// FileExtension returns ".csv".
func (f *CSVFormatter) FileExtension() string {
	return ".csv"
}
