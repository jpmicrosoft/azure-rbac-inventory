package output

import (
	"fmt"

	"github.com/xuri/excelize/v2"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	reportpkg "github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// XLSXFormatter renders reports as Excel workbooks.
type XLSXFormatter struct{}

func (XLSXFormatter) FileExtension() string { return ".xlsx" }

// xlsxHeaderStyle returns an excelize style ID for header rows.
func xlsxHeaderStyle(f *excelize.File) (int, error) {
	return f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF", Size: 11},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"#2B5797"}},
		Alignment: &excelize.Alignment{Vertical: "center", WrapText: true},
		Border: []excelize.Border{
			{Type: "bottom", Color: "#1a3a6b", Style: 2},
		},
	})
}

// xlsxSetHeaders writes a header row, applies style, auto-filter, and freeze pane.
func xlsxSetHeaders(f *excelize.File, sheet string, headers []string, style int) error {
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		if err := f.SetCellValue(sheet, cell, h); err != nil {
			return err
		}
		if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
			return err
		}
	}
	lastCol, _ := excelize.CoordinatesToCellName(len(headers), 1)
	if err := f.AutoFilter(sheet, "A1:"+lastCol, nil); err != nil {
		return err
	}
	return f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	})
}

// xlsxAutoWidth sets column widths based on header and data content.
func xlsxAutoWidth(f *excelize.File, sheet string, headers []string, rows [][]string) {
	widths := make([]float64, len(headers))
	for i, h := range headers {
		widths[i] = float64(len(h))
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && float64(len(cell)) > widths[i] {
				widths[i] = float64(len(cell))
			}
		}
	}
	for i, w := range widths {
		col, _ := excelize.ColumnNumberToName(i + 1)
		width := w + 4
		if width > 60 {
			width = 60
		}
		if width < 10 {
			width = 10
		}
		_ = f.SetColWidth(sheet, col, col, width)
	}
}

// xlsxWriteRows writes data rows starting at row 2.
func xlsxWriteRows(f *excelize.File, sheet string, rows [][]string) error {
	for r, row := range rows {
		for c, val := range row {
			cell, _ := excelize.CoordinatesToCellName(c+1, r+2)
			if err := f.SetCellValue(sheet, cell, val); err != nil {
				return err
			}
		}
	}
	return nil
}

// xlsxWriteSheet creates a sheet with headers and data rows.
func xlsxWriteSheet(f *excelize.File, sheet string, hStyle int, headers []string, rows [][]string) error {
	if _, err := f.NewSheet(sheet); err != nil {
		return fmt.Errorf("xlsx new sheet error: %w", err)
	}
	if err := xlsxSetHeaders(f, sheet, headers, hStyle); err != nil {
		return err
	}
	if err := xlsxWriteRows(f, sheet, rows); err != nil {
		return err
	}
	xlsxAutoWidth(f, sheet, headers, rows)
	return nil
}

func (x XLSXFormatter) FormatReport(rpt *reportpkg.Report) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	hStyle, err := xlsxHeaderStyle(f)
	if err != nil {
		return nil, fmt.Errorf("xlsx style error: %w", err)
	}

	// Summary
	summaryRows := [][]string{
		{"Display Name", rpt.Identity.DisplayName},
		{"Object ID", rpt.Identity.ObjectID},
		{"Type", string(rpt.Identity.Type)},
		{"Cloud", rpt.Cloud},
	}
	if rpt.Identity.AppID != "" {
		summaryRows = append(summaryRows, []string{"App ID", rpt.Identity.AppID})
	}
	if rpt.Identity.ServicePrincipalType != "" {
		summaryRows = append(summaryRows, []string{"SPN Type", rpt.Identity.ServicePrincipalType})
	}
	if err := xlsxWriteSheet(f, "Summary", hStyle, []string{"Property", "Value"}, summaryRows); err != nil {
		return nil, err
	}

	// RBAC Assignments
	if err := xlsxWriteSheet(f, "RBAC Assignments", hStyle,
		[]string{"Role Name", "Scope", "Scope Type", "Assignment Type", "Principal Type", "Condition"},
		rbacToRows(rpt.RBACAssignments)); err != nil {
		return nil, err
	}

	// Directory Roles
	if err := xlsxWriteSheet(f, "Directory Roles", hStyle,
		[]string{"Role Name", "Role ID", "Status"},
		directoryRolesToRows(rpt.DirectoryRoles)); err != nil {
		return nil, err
	}

	// Access Packages
	if err := xlsxWriteSheet(f, "Access Packages", hStyle,
		[]string{"Package Name", "Catalog", "Status", "Expiration Date"},
		accessPackagesToRows(rpt.AccessPackages)); err != nil {
		return nil, err
	}

	// Access Requests
	if err := xlsxWriteSheet(f, "Access Requests", hStyle,
		[]string{"Package Name", "Request Type", "Status", "Created Date"},
		accessRequestsToRows(rpt.AccessRequests)); err != nil {
		return nil, err
	}

	// Group Memberships
	if err := xlsxWriteSheet(f, "Group Memberships", hStyle,
		[]string{"Group Name", "Group Type", "Membership"},
		groupsToRows(rpt.GroupMemberships)); err != nil {
		return nil, err
	}

	// Warnings (only if present)
	if len(rpt.Warnings) > 0 {
		if err := xlsxWriteSheet(f, "Warnings", hStyle,
			[]string{"Warning"}, warningsToRows(rpt.Warnings)); err != nil {
			return nil, err
		}
	}

	f.DeleteSheet("Sheet1")

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("xlsx write error: %w", err)
	}
	return buf.Bytes(), nil
}

func (x XLSXFormatter) FormatMultiReport(reports []*reportpkg.Report) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	hStyle, err := xlsxHeaderStyle(f)
	if err != nil {
		return nil, fmt.Errorf("xlsx style error: %w", err)
	}

	// Collect all data across reports with an Identity column prefix.
	var (
		summaryRows [][]string
		allRBAC     [][]string
		allDirRoles [][]string
		allPkgs     [][]string
		allReqs     [][]string
		allGroups   [][]string
		allWarnings [][]string
	)

	for _, rpt := range reports {
		name := rpt.Identity.DisplayName

		summaryRows = append(summaryRows, []string{
			name, rpt.Identity.ObjectID, string(rpt.Identity.Type),
			rpt.Identity.AppID, rpt.Identity.ServicePrincipalType, rpt.Cloud,
		})

		for _, a := range rpt.RBACAssignments {
			allRBAC = append(allRBAC, []string{name, a.RoleName, a.Scope, a.ScopeType, a.AssignmentType, a.PrincipalType, a.Condition})
		}
		for _, d := range rpt.DirectoryRoles {
			allDirRoles = append(allDirRoles, []string{name, d.RoleName, d.RoleID, d.Status})
		}
		for _, p := range rpt.AccessPackages {
			allPkgs = append(allPkgs, []string{name, p.PackageName, p.CatalogName, p.Status, p.ExpirationDate})
		}
		for _, r := range rpt.AccessRequests {
			allReqs = append(allReqs, []string{name, r.PackageName, r.RequestType, r.Status, r.CreatedDate})
		}
		for _, g := range rpt.GroupMemberships {
			allGroups = append(allGroups, []string{name, g.GroupName, g.GroupType, g.Membership})
		}
		for _, w := range rpt.Warnings {
			allWarnings = append(allWarnings, []string{fmt.Sprintf("[%s] %s", name, w)})
		}
	}

	if err := xlsxWriteSheet(f, "Summary", hStyle,
		[]string{"Display Name", "Object ID", "Type", "App ID", "SPN Type", "Cloud"}, summaryRows); err != nil {
		return nil, err
	}
	if err := xlsxWriteSheet(f, "RBAC Assignments", hStyle,
		[]string{"Identity", "Role Name", "Scope", "Scope Type", "Assignment Type", "Principal Type", "Condition"}, allRBAC); err != nil {
		return nil, err
	}
	if err := xlsxWriteSheet(f, "Directory Roles", hStyle,
		[]string{"Identity", "Role Name", "Role ID", "Status"}, allDirRoles); err != nil {
		return nil, err
	}
	if err := xlsxWriteSheet(f, "Access Packages", hStyle,
		[]string{"Identity", "Package Name", "Catalog", "Status", "Expiration Date"}, allPkgs); err != nil {
		return nil, err
	}
	if err := xlsxWriteSheet(f, "Access Requests", hStyle,
		[]string{"Identity", "Package Name", "Request Type", "Status", "Created Date"}, allReqs); err != nil {
		return nil, err
	}
	if err := xlsxWriteSheet(f, "Group Memberships", hStyle,
		[]string{"Identity", "Group Name", "Group Type", "Membership"}, allGroups); err != nil {
		return nil, err
	}
	if len(allWarnings) > 0 {
		if err := xlsxWriteSheet(f, "Warnings", hStyle,
			[]string{"Warning"}, allWarnings); err != nil {
			return nil, err
		}
	}

	f.DeleteSheet("Sheet1")

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("xlsx write error: %w", err)
	}
	return buf.Bytes(), nil
}

// ── Row conversion helpers ───────────────────────────────────────────────────

func rbacToRows(assignments []rbac.RoleAssignment) [][]string {
	rows := make([][]string, len(assignments))
	for i, a := range assignments {
		rows[i] = []string{a.RoleName, a.Scope, a.ScopeType, a.AssignmentType, a.PrincipalType, a.Condition}
	}
	return rows
}

func directoryRolesToRows(roles []graph.DirectoryRole) [][]string {
	rows := make([][]string, len(roles))
	for i, r := range roles {
		rows[i] = []string{r.RoleName, r.RoleID, r.Status}
	}
	return rows
}

func accessPackagesToRows(pkgs []graph.AccessPackageAssignment) [][]string {
	rows := make([][]string, len(pkgs))
	for i, p := range pkgs {
		rows[i] = []string{p.PackageName, p.CatalogName, p.Status, p.ExpirationDate}
	}
	return rows
}

func accessRequestsToRows(reqs []graph.AccessPackageRequest) [][]string {
	rows := make([][]string, len(reqs))
	for i, r := range reqs {
		rows[i] = []string{r.PackageName, r.RequestType, r.Status, r.CreatedDate}
	}
	return rows
}

func groupsToRows(groups []graph.GroupMembership) [][]string {
	rows := make([][]string, len(groups))
	for i, g := range groups {
		rows[i] = []string{g.GroupName, g.GroupType, g.Membership}
	}
	return rows
}

func warningsToRows(warnings []string) [][]string {
	rows := make([][]string, len(warnings))
	for i, w := range warnings {
		rows[i] = []string{w}
	}
	return rows
}
