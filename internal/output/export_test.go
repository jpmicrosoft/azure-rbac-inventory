package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/graph"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/identity"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/rbac"
	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// makeTestReport builds a report with representative data for export tests.
func makeTestReport() *report.Report {
	return &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Test SPN",
			Type:        identity.TypeServicePrincipal,
			AppID:       "app-id-123",
		},
		Cloud: "AzureCloud",
		RBACAssignments: []rbac.RoleAssignment{
			{RoleName: "Reader", Scope: "/subscriptions/sub1", ScopeType: "Subscription", AssignmentType: "Direct", PrincipalType: "ServicePrincipal"},
			{RoleName: "Contributor", Scope: "/subscriptions/sub1/resourceGroups/rg1", ScopeType: "Resource Group", AssignmentType: "Direct"},
		},
		DirectoryRoles:   []graph.DirectoryRole{{RoleName: "Global Reader", Status: "Active"}},
		AccessPackages:   []graph.AccessPackageAssignment{{PackageName: "Dev Access", CatalogName: "IT", Status: "Delivered"}},
		GroupMemberships: []graph.GroupMembership{{GroupName: "Developers", GroupType: "Security", Membership: "Direct"}},
	}
}

// ---------------------------------------------------------------------------
// CSV Formatter tests
// ---------------------------------------------------------------------------

func TestCSVFormatter_FormatReport(t *testing.T) {
	rpt := makeTestReport()
	f := &CSVFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}

	// Skip BOM bytes (3 bytes)
	content := data[len(csvBOM):]
	r := csv.NewReader(bytes.NewReader(content))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV: %v", err)
	}

	// Verify header row
	header := records[0]
	for i, want := range csvHeader {
		if i >= len(header) {
			t.Errorf("header missing column %d: want %q", i, want)
			continue
		}
		if header[i] != want {
			t.Errorf("header[%d] = %q, want %q", i, header[i], want)
		}
	}

	// Expected rows: 2 RBAC + 1 DirectoryRole + 1 AccessPackage + 1 GroupMembership = 5
	wantDataRows := 5
	gotDataRows := len(records) - 1
	if gotDataRows != wantDataRows {
		t.Errorf("expected %d data rows, got %d", wantDataRows, gotDataRows)
	}

	// Spot-check first RBAC row values
	if len(records) > 1 {
		row := records[1]
		if row[0] != "Test SPN" {
			t.Errorf("Identity = %q, want %q", row[0], "Test SPN")
		}
		if row[4] != "RBAC" {
			t.Errorf("Category = %q, want %q", row[4], "RBAC")
		}
		if row[5] != "Reader" {
			t.Errorf("Name = %q, want %q", row[5], "Reader")
		}
	}
}

func TestCSVFormatter_BOM(t *testing.T) {
	rpt := makeTestReport()
	f := &CSVFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}

	if len(data) < 3 {
		t.Fatal("output too short to contain BOM")
	}
	if data[0] != 0xEF || data[1] != 0xBB || data[2] != 0xBF {
		t.Errorf("expected UTF-8 BOM (EF BB BF), got: %02x %02x %02x", data[0], data[1], data[2])
	}
}

func TestCSVFormatter_EmptyReport(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Empty Identity",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
	}

	f := &CSVFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}

	// Skip BOM
	content := data[len(csvBOM):]
	r := csv.NewReader(bytes.NewReader(content))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV: %v", err)
	}

	if len(records) != 1 {
		t.Errorf("expected 1 row (header only), got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// Markdown Formatter tests
// ---------------------------------------------------------------------------

func TestMarkdownFormatter_FormatReport(t *testing.T) {
	rpt := makeTestReport()
	f := &MarkdownFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}
	md := string(data)

	// Verify ## header
	if !strings.Contains(md, "## Identity Report: Test SPN") {
		t.Error("expected ## Identity Report header")
	}

	// Verify ### section headers
	if !strings.Contains(md, "### Azure Role Assignments (2)") {
		t.Error("expected ### Azure Role Assignments section with count 2")
	}

	// Verify pipe tables
	if !strings.Contains(md, "| Role |") {
		t.Error("expected markdown pipe table for RBAC")
	}
	if !strings.Contains(md, "| Reader |") {
		t.Error("expected Reader role in table")
	}

	// Verify section counts
	if !strings.Contains(md, "### Entra ID Directory Roles (1)") {
		t.Error("expected directory roles section with count 1")
	}
	if !strings.Contains(md, "### Access Package Assignments (1)") {
		t.Error("expected access packages section with count 1")
	}
	if !strings.Contains(md, "### Group Memberships (1)") {
		t.Error("expected group memberships section with count 1")
	}
}

func TestMarkdownFormatter_EmptyReport(t *testing.T) {
	rpt := &report.Report{
		Identity: &identity.Identity{
			ObjectID:    "00000000-0000-0000-0000-000000000001",
			DisplayName: "Empty",
			Type:        identity.TypeUser,
		},
		Cloud: "AzureCloud",
	}

	f := &MarkdownFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}
	md := string(data)

	if !strings.Contains(md, "_No results found._") {
		t.Error("empty sections should show '_No results found._'")
	}

	// All sections should show (0)
	if !strings.Contains(md, "### Azure Role Assignments (0)") {
		t.Error("expected RBAC section with count 0")
	}
}

// ---------------------------------------------------------------------------
// HTML Formatter tests
// ---------------------------------------------------------------------------

func TestHTMLFormatter_FormatReport(t *testing.T) {
	rpt := makeTestReport()
	f := HTMLFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}
	html := string(data)

	if !strings.Contains(html, "<html") {
		t.Error("expected <html> tag")
	}
	if !strings.Contains(html, "<style>") {
		t.Error("expected <style> tag")
	}
	if !strings.Contains(html, "<details") {
		t.Error("expected <details> element")
	}
	if !strings.Contains(html, "Test SPN") {
		t.Error("expected identity display name in HTML")
	}
	if !strings.Contains(html, "Reader") {
		t.Error("expected role name in HTML")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("expected closing </html> tag")
	}
}

// ---------------------------------------------------------------------------
// XLSX Formatter tests
// ---------------------------------------------------------------------------

func TestXLSXFormatter_FormatReport(t *testing.T) {
	rpt := makeTestReport()
	f := XLSXFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}

	xlsx, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to open XLSX output: %v", err)
	}
	defer func() { _ = xlsx.Close() }()

	sheets := xlsx.GetSheetList()
	expectedSheets := []string{
		"Summary",
		"RBAC Assignments",
		"Directory Roles",
		"Access Packages",
		"Access Requests",
		"Group Memberships",
	}
	for _, want := range expectedSheets {
		found := false
		for _, got := range sheets {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sheet %q not found in %v", want, sheets)
		}
	}

	// Verify "Sheet1" was removed
	for _, s := range sheets {
		if s == "Sheet1" {
			t.Error("default Sheet1 should have been removed")
		}
	}
}

// ---------------------------------------------------------------------------
// JSON Formatter tests
// ---------------------------------------------------------------------------

func TestJSONFormatter_FormatReport(t *testing.T) {
	rpt := makeTestReport()
	f := &JSONFormatter{}
	data, err := f.FormatReport(rpt)
	if err != nil {
		t.Fatalf("FormatReport error: %v", err)
	}

	// Must be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify expected top-level fields
	expectedFields := []string{"identity", "cloud", "rbacAssignments", "directoryRoles",
		"accessPackageAssignments", "accessPackageRequests", "groupMemberships"}
	for _, field := range expectedFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("expected field %q not found in JSON", field)
		}
	}

	// Verify identity values
	ident, ok := parsed["identity"].(map[string]interface{})
	if !ok {
		t.Fatal("identity field is not a JSON object")
	}
	if ident["displayName"] != "Test SPN" {
		t.Errorf("displayName = %v, want %q", ident["displayName"], "Test SPN")
	}
	if ident["objectId"] != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("objectId = %v, want correct UUID", ident["objectId"])
	}

	// Verify cloud
	if parsed["cloud"] != "AzureCloud" {
		t.Errorf("cloud = %v, want %q", parsed["cloud"], "AzureCloud")
	}
}

// ---------------------------------------------------------------------------
// ExportFile tests
// ---------------------------------------------------------------------------

func TestExportFile_CSVExtension(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "output.csv")
	rpt := makeTestReport()

	err := ExportFile(rpt, filePath)
	if err != nil {
		t.Fatalf("ExportFile error: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("exported CSV file is empty")
	}

	// Verify content is valid CSV
	data, _ := os.ReadFile(filePath)
	content := data[len(csvBOM):]
	r := csv.NewReader(bytes.NewReader(content))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("exported file is not valid CSV: %v", err)
	}
	if len(records) < 2 {
		t.Error("expected at least header + data rows")
	}
}

func TestExportFile_JSONExtension(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "output.json")
	rpt := makeTestReport()

	err := ExportFile(rpt, filePath)
	if err != nil {
		t.Fatalf("ExportFile error: %v", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("exported JSON is not valid: %v", err)
	}
}

func TestExportFile_MarkdownExtension(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "output.md")
	rpt := makeTestReport()

	err := ExportFile(rpt, filePath)
	if err != nil {
		t.Fatalf("ExportFile error: %v", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(data), "## Identity Report") {
		t.Error("exported markdown missing expected header")
	}
}

func TestExportFile_UnknownExtension(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "output.xyz")
	rpt := makeTestReport()

	err := ExportFile(rpt, filePath)
	if err == nil {
		t.Fatal("expected error for unsupported extension, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported file extension") {
		t.Errorf("error = %v, want 'unsupported file extension'", err)
	}
}

// ---------------------------------------------------------------------------
// GetFormatter tests
// ---------------------------------------------------------------------------

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantType string // expected concrete type name (empty = expect error)
		wantErr  bool
	}{
		{"json", "json", "*output.JSONFormatter", false},
		{"csv", "csv", "*output.CSVFormatter", false},
		{"markdown", "markdown", "*output.MarkdownFormatter", false},
		{"md alias", "md", "*output.MarkdownFormatter", false},
		{"html", "html", "*output.HTMLFormatter", false},
		{"xlsx", "xlsx", "*output.XLSXFormatter", false},
		{"unknown format", "yaml", "", true},
		{"empty format", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := GetFormatter(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetFormatter(%q) expected error, got nil", tt.format)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetFormatter(%q) unexpected error: %v", tt.format, err)
			}
			if f == nil {
				t.Fatalf("GetFormatter(%q) returned nil formatter", tt.format)
			}
		})
	}
}
