package output

import (
	"encoding/json"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// JSONFormatter implements the Formatter interface for JSON output.
type JSONFormatter struct{}

// FormatReport formats a single identity report as indented JSON.
func (f *JSONFormatter) FormatReport(rpt *report.Report) ([]byte, error) {
	return json.MarshalIndent(reportForSerialization(rpt), "", "  ")
}

// FormatMultiReport formats multiple identity reports as indented JSON.
func (f *JSONFormatter) FormatMultiReport(reports []*report.Report) ([]byte, error) {
	outputReports := make([]*report.Report, len(reports))
	for i, rpt := range reports {
		outputReports[i] = reportForSerialization(rpt)
	}
	return json.MarshalIndent(outputReports, "", "  ")
}

func reportForSerialization(rpt *report.Report) *report.Report {
	if rpt == nil || !rpt.LegacyOutput {
		return rpt
	}
	copy := *rpt
	copy.ManagementGroupNames = nil
	return &copy
}

// FileExtension returns ".json".
func (f *JSONFormatter) FileExtension() string {
	return ".json"
}
