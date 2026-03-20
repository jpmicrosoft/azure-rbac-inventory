package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Text input tests (existing behaviour, adapted for []InputEntry)
// ---------------------------------------------------------------------------

func TestParseInputFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.txt")

	content := `# This is a comment
00000000-0000-0000-0000-000000000001
  
00000000-0000-0000-0000-000000000002
# Another comment

spn-*
00000000-0000-0000-0000-000000000003
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"spn-*",
		"00000000-0000-0000-0000-000000000003",
	}

	if len(results) != len(expected) {
		t.Fatalf("expected %d entries, got %d: %v", len(expected), len(results), results)
	}
	for i, want := range expected {
		if results[i].ID != want {
			t.Errorf("entry %d: expected ID %q, got %q", i, want, results[i].ID)
		}
	}
}

func TestParseInputFile_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comments_only.txt")

	content := `# comment one
# comment two

   
	
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for file with only comments and blanks, got nil")
	}
	if !strings.Contains(err.Error(), "no valid entries") {
		t.Errorf("expected error containing %q, got: %v", "no valid entries", err)
	}
}

func TestParseInputFile_NonexistentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does_not_exist.txt")

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "cannot open file") {
		t.Errorf("expected error containing %q, got: %v", "cannot open file", err)
	}
}

func TestParseInputFile_WhitespaceHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitespace.txt")

	content := "  00000000-0000-0000-0000-000000000001  \n" +
		"\t00000000-0000-0000-0000-000000000002\t\n" +
		"  \t  some-display-name  \t  \n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"some-display-name",
	}

	if len(results) != len(expected) {
		t.Fatalf("expected %d entries, got %d: %v", len(expected), len(results), results)
	}
	for i, want := range expected {
		if results[i].ID != want {
			t.Errorf("entry %d: expected ID %q, got %q", i, want, results[i].ID)
		}
	}
}

func TestParseInputFile_MixedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.txt")

	content := `# Service principals to check
00000000-0000-0000-0000-000000000001
spn-*
# Production wildcards
*prod*
My Display Name
  11111111-1111-1111-1111-111111111111  

# end of file
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"00000000-0000-0000-0000-000000000001",
		"spn-*",
		"*prod*",
		"My Display Name",
		"11111111-1111-1111-1111-111111111111",
	}

	if len(results) != len(expected) {
		t.Fatalf("expected %d entries, got %d: %v", len(expected), len(results), results)
	}
	for i, want := range expected {
		if results[i].ID != want {
			t.Errorf("entry %d: expected ID %q, got %q", i, want, results[i].ID)
		}
	}
}

// ---------------------------------------------------------------------------
// CSV input tests
// ---------------------------------------------------------------------------

func TestParseInputFile_CSV_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.csv")

	content := "id,type,label\n" +
		"uuid-1,spn,My SPN\n" +
		"uuid-2,user,A User\n" +
		"uuid-3,,No Type\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(results))
	}
	if results[0].ID != "uuid-1" || results[0].Type != "spn" || results[0].Label != "My SPN" {
		t.Errorf("entry 0 mismatch: %+v", results[0])
	}
	if results[2].Type != "" {
		t.Errorf("entry 2 type should be empty, got %q", results[2].Type)
	}
}

func TestParseInputFile_CSV_MissingIDColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csv")

	content := "name,type\nfoo,spn\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for missing id column")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("expected error about id column, got: %v", err)
	}
}

func TestParseInputFile_CSV_InvalidType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badtype.csv")

	content := "id,type\nuuid-1,bogus\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "invalid identity type") {
		t.Errorf("expected error about invalid type, got: %v", err)
	}
}

func TestParseInputFile_CSV_SkipsEmptyID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emptyid.csv")

	content := "id,type\nuuid-1,spn\n,user\nuuid-2,group\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entries (skipping empty id), got %d", len(results))
	}
}

func TestParseInputFile_CSV_OptionalColumns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idonly.csv")

	content := "id\nuuid-1\nuuid-2\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
	for i, r := range results {
		if r.Type != "" {
			t.Errorf("entry %d: expected empty Type, got %q", i, r.Type)
		}
		if r.Label != "" {
			t.Errorf("entry %d: expected empty Label, got %q", i, r.Label)
		}
	}
}

func TestParseInputFile_CSV_EmptyIDSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emptyids.csv")

	content := "id,type\nuuid-1,spn\n,user\n  ,group\nuuid-2,\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entries (empty IDs skipped), got %d", len(results))
	}
	if results[0].ID != "uuid-1" || results[1].ID != "uuid-2" {
		t.Errorf("expected uuid-1 and uuid-2, got %q and %q", results[0].ID, results[1].ID)
	}
}

func TestParseInputFile_CSV_ColumnOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reordered.csv")

	content := "label,id,type\nMy SPN,uuid-1,spn\nA User,uuid-2,user\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
	if results[0].ID != "uuid-1" || results[0].Type != "spn" || results[0].Label != "My SPN" {
		t.Errorf("entry 0 mismatch: %+v", results[0])
	}
	if results[1].ID != "uuid-2" || results[1].Type != "user" || results[1].Label != "A User" {
		t.Errorf("entry 1 mismatch: %+v", results[1])
	}
}

func TestParseInputFile_CSV_WhitespaceInValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ws.csv")

	content := "id,type,label\n  uuid-1  , spn , My SPN \n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(results))
	}
	if results[0].ID != "uuid-1" {
		t.Errorf("expected trimmed ID %q, got %q", "uuid-1", results[0].ID)
	}
	if results[0].Type != "spn" {
		t.Errorf("expected trimmed Type %q, got %q", "spn", results[0].Type)
	}
	if results[0].Label != "My SPN" {
		t.Errorf("expected trimmed Label %q, got %q", "My SPN", results[0].Label)
	}
}

// ---------------------------------------------------------------------------
// JSON input tests
// ---------------------------------------------------------------------------

func TestParseInputFile_JSON_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")

	data := map[string]interface{}{
		"identities": []map[string]string{
			{"id": "uuid-1", "type": "spn", "label": "First"},
			{"id": "uuid-2"},
		},
	}
	b, _ := json.Marshal(data)
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
	if results[0].ID != "uuid-1" || results[0].Type != "spn" || results[0].Label != "First" {
		t.Errorf("entry 0 mismatch: %+v", results[0])
	}
	if results[1].Type != "" || results[1].Label != "" {
		t.Errorf("entry 1 should have empty type/label: %+v", results[1])
	}
}

func TestParseInputFile_JSON_MissingIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for missing identities key")
	}
	if !strings.Contains(err.Error(), "identities") {
		t.Errorf("expected error about identities, got: %v", err)
	}
}

func TestParseInputFile_JSON_EmptyID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noid.json")

	content := `{"identities": [{"id": "", "type": "spn"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for empty id")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("expected error about id, got: %v", err)
	}
}

func TestParseInputFile_JSON_InvalidType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badtype.json")

	content := `{"identities": [{"id": "uuid-1", "type": "invalid"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "invalid identity type") {
		t.Errorf("expected error about invalid type, got: %v", err)
	}
}

func TestParseInputFile_JSON_OptionalFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "optional.json")

	content := `{"identities": [{"id": "uuid-1"}, {"id": "uuid-2"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
	for i, r := range results {
		if r.Type != "" {
			t.Errorf("entry %d: expected empty Type, got %q", i, r.Type)
		}
		if r.Label != "" {
			t.Errorf("entry %d: expected empty Label, got %q", i, r.Label)
		}
	}
}

func TestParseInputFile_JSON_MissingIdentitiesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nokey.json")

	content := `{"items": [{"id": "uuid-1"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for missing identities key")
	}
	if !strings.Contains(err.Error(), "identities") {
		t.Errorf("expected error about identities, got: %v", err)
	}
}

func TestParseInputFile_JSON_EmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emptyarr.json")

	content := `{"identities": []}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for empty identities array")
	}
	if !strings.Contains(err.Error(), "identities") {
		t.Errorf("expected error about identities, got: %v", err)
	}
}

func TestParseInputFile_JSON_MissingID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missingid.json")

	content := `{"identities": [{"type": "spn", "label": "No ID"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := ParseInputFile(path)
	if err == nil {
		t.Fatal("expected error for missing id field")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("expected error about id, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Auto-detection tests
// ---------------------------------------------------------------------------

func TestParseInputFile_AutoDetect_CSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.csv")

	content := "id,type\nuuid-1,spn\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].ID != "uuid-1" || results[0].Type != "spn" {
		t.Errorf("CSV auto-detect failed: %+v", results)
	}
}

func TestParseInputFile_AutoDetect_JSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	content := `{"identities": [{"id": "uuid-1", "type": "spn"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].ID != "uuid-1" || results[0].Type != "spn" {
		t.Errorf("JSON auto-detect failed: %+v", results)
	}
}

func TestParseInputFile_AutoDetect_TXT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	content := "uuid-1\nuuid-2\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
	for i, r := range results {
		if r.Type != "" || r.Label != "" {
			t.Errorf("entry %d: text parser should not set Type or Label: %+v", i, r)
		}
	}
}

func TestParseInputFile_AutoDetect_NoExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identities")

	content := "uuid-1\nuuid-2\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	results, err := ParseInputFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// ValidateInputType tests
// ---------------------------------------------------------------------------

func TestValidateInputType(t *testing.T) {
	validCases := []string{"", "spn", "user", "group", "managed-identity", "app", "all"}
	for _, v := range validCases {
		if err := ValidateInputType(v); err != nil {
			t.Errorf("ValidateInputType(%q) returned unexpected error: %v", v, err)
		}
	}

	invalidCases := []string{"bogus", "SPN!", "managed_identity", "admin"}
	for _, v := range invalidCases {
		if err := ValidateInputType(v); err == nil {
			t.Errorf("ValidateInputType(%q) should have returned an error", v)
		}
	}
}
