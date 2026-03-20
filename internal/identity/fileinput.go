package identity

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxInputEntries is the maximum number of entries allowed in an input file.
const maxInputEntries = 10000

// maxInputFileBytes is the maximum file size allowed for input files (10 MB).
const maxInputFileBytes = 10 * 1024 * 1024

// InputEntry represents a single identity input with optional metadata.
type InputEntry struct {
	ID    string `json:"id"`    // Required: UUID, app ID, display name, or wildcard pattern
	Type  string `json:"type"`  // Optional: identity type filter (spn, user, group, managed-identity, app, all)
	Label string `json:"label"` // Optional: descriptive label shown in report output
}

// validTypes is the set of accepted identity type values.
var validTypes = map[string]bool{
	"":                 true,
	"all":              true,
	"spn":              true,
	"user":             true,
	"group":            true,
	"managed-identity": true,
	"app":              true,
}

// ValidateInputType checks whether t is a recognised identity type filter.
// Valid values are "", "all", "spn", "user", "group", "managed-identity", and "app".
func ValidateInputType(t string) error {
	if validTypes[strings.ToLower(t)] {
		return nil
	}
	return fmt.Errorf("invalid identity type %q: must be one of spn, user, group, managed-identity, app, all (or empty)", t)
}

// ParseInputFile reads an input file and returns a slice of InputEntry values.
// The file format is auto-detected by extension:
//   - .csv  → CSV with header row (id required, type and label optional)
//   - .json → JSON with {"identities": [...]} structure
//   - anything else → plain text, one ID per line
func ParseInputFile(path string) ([]InputEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot stat file %q: %w", path, err)
	}
	if info.Size() > maxInputFileBytes {
		return nil, fmt.Errorf("file %q is %d bytes, exceeding maximum of %d (10 MB)", path, info.Size(), maxInputFileBytes)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csv":
		return parseCSVInput(path)
	case ".json":
		return parseJSONInput(path)
	default:
		return parseTextInput(path)
	}
}

// parseTextInput reads a plain-text file with one identity ID per line.
// Lines starting with '#' are treated as comments. Empty/whitespace-only lines are skipped.
func parseTextInput(path string) ([]InputEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", path, err)
	}
	defer f.Close()

	var entries []InputEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, InputEntry{ID: line})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %q: %w", path, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no valid entries found in file %q", path)
	}
	if len(entries) > maxInputEntries {
		return nil, fmt.Errorf("file %q contains %d entries, exceeding maximum of %d", path, len(entries), maxInputEntries)
	}
	return entries, nil
}

// parseCSVInput reads a CSV file with a header row.
// The header must contain an "id" column (case-insensitive). Optional columns: "type", "label".
func parseCSVInput(path string) ([]InputEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", path, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV file %q: %w", path, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("CSV file %q is empty", path)
	}

	// Map header names to column indices.
	header := records[0]
	colIndex := make(map[string]int)
	for i, h := range header {
		colIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	idIdx, ok := colIndex["id"]
	if !ok {
		return nil, fmt.Errorf("CSV file %q: header row must contain an \"id\" column", path)
	}
	typeIdx, hasType := colIndex["type"]
	labelIdx, hasLabel := colIndex["label"]

	var entries []InputEntry
	for rowNum, row := range records[1:] {
		id := strings.TrimSpace(row[idIdx])
		if id == "" {
			continue
		}

		entry := InputEntry{ID: id}

		if hasType && typeIdx < len(row) {
			entry.Type = strings.TrimSpace(row[typeIdx])
			if err := ValidateInputType(entry.Type); err != nil {
				return nil, fmt.Errorf("CSV file %q row %d: %w", path, rowNum+2, err)
			}
		}
		if hasLabel && labelIdx < len(row) {
			entry.Label = strings.TrimSpace(row[labelIdx])
		}

		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no valid data rows found in CSV file %q", path)
	}
	if len(entries) > maxInputEntries {
		return nil, fmt.Errorf("CSV file %q contains %d entries, exceeding maximum of %d", path, len(entries), maxInputEntries)
	}
	return entries, nil
}

// jsonInputWrapper is the top-level JSON structure for identity input files.
type jsonInputWrapper struct {
	Identities []jsonInputEntry `json:"identities"`
}

// jsonInputEntry mirrors InputEntry for JSON unmarshalling with pointer fields
// to distinguish missing from empty.
type jsonInputEntry struct {
	ID    *string `json:"id"`
	Type  string  `json:"type"`
	Label string  `json:"label"`
}

// parseJSONInput reads a JSON file with an {"identities": [...]} structure.
func parseJSONInput(path string) ([]InputEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", path, err)
	}
	defer f.Close()

	var wrapper jsonInputWrapper
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("error parsing JSON file %q: %w", path, err)
	}

	if len(wrapper.Identities) == 0 {
		return nil, fmt.Errorf("JSON file %q: \"identities\" key is missing or empty", path)
	}

	if len(wrapper.Identities) > maxInputEntries {
		return nil, fmt.Errorf("JSON file %q contains %d entries, exceeding maximum of %d", path, len(wrapper.Identities), maxInputEntries)
	}

	var entries []InputEntry
	for i, item := range wrapper.Identities {
		if item.ID == nil || strings.TrimSpace(*item.ID) == "" {
			return nil, fmt.Errorf("JSON file %q entry %d: \"id\" is required and must not be empty", path, i)
		}
		id := strings.TrimSpace(*item.ID)
		typ := strings.TrimSpace(item.Type)
		if err := ValidateInputType(typ); err != nil {
			return nil, fmt.Errorf("JSON file %q entry %d: %w", path, i, err)
		}
		entries = append(entries, InputEntry{
			ID:    id,
			Type:  typ,
			Label: strings.TrimSpace(item.Label),
		})
	}

	return entries, nil
}
