package output

import (
	"encoding/json"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// JSONFormatter implements the Formatter interface for JSON output.
type JSONFormatter struct{}

// FormatReport formats a single identity report as indented JSON.
func (f *JSONFormatter) FormatReport(rpt *report.Report) ([]byte, error) {
	return json.MarshalIndent(rpt, "", "  ")
}

// FormatMultiReport formats multiple identity reports as indented JSON.
func (f *JSONFormatter) FormatMultiReport(reports []*report.Report) ([]byte, error) {
	return json.MarshalIndent(reports, "", "  ")
}

// FileExtension returns ".json".
func (f *JSONFormatter) FileExtension() string {
	return ".json"
}
