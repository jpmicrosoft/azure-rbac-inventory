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
	"Detail", "Status", "AssignmentType",
}

// CSVFormatter implements the Formatter interface for CSV output.
type CSVFormatter struct{}

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
	if err := w.Write(csvHeader); err != nil {
		return nil, err
	}

	for _, rpt := range reports {
		name := rpt.Identity.DisplayName
		objectID := rpt.Identity.ObjectID
		idType := string(rpt.Identity.Type)
		cloud := rpt.Cloud

		for _, a := range rpt.RBACAssignments {
			if err := w.Write([]string{
				name, objectID, idType, cloud,
				"RBAC", a.RoleName, a.Scope, a.ScopeType,
				a.PrincipalType, "", a.AssignmentType,
			}); err != nil {
				return nil, err
			}
		}

		for _, r := range rpt.DirectoryRoles {
			if err := w.Write([]string{
				name, objectID, idType, cloud,
				"DirectoryRole", r.RoleName, "", "",
				r.RoleID, r.Status, "",
			}); err != nil {
				return nil, err
			}
		}

		for _, p := range rpt.AccessPackages {
			if err := w.Write([]string{
				name, objectID, idType, cloud,
				"AccessPackage", p.PackageName, "", "",
				p.CatalogName, p.Status, p.ExpirationDate,
			}); err != nil {
				return nil, err
			}
		}

		for _, r := range rpt.AccessRequests {
			if err := w.Write([]string{
				name, objectID, idType, cloud,
				"AccessPackageRequest", r.PackageName, "", "",
				r.RequestType, r.Status, r.CreatedDate,
			}); err != nil {
				return nil, err
			}
		}

		for _, g := range rpt.GroupMemberships {
			if err := w.Write([]string{
				name, objectID, idType, cloud,
				"GroupMembership", g.GroupName, "", "",
				g.GroupType, "", g.Membership,
			}); err != nil {
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

// FileExtension returns ".csv".
func (f *CSVFormatter) FileExtension() string {
	return ".csv"
}
