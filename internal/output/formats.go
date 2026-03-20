package output

import (
	"fmt"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// Formatter defines the interface for report export formats.
type Formatter interface {
	// FormatReport formats a single identity report.
	FormatReport(rpt *report.Report) ([]byte, error)
	// FormatMultiReport formats multiple identity reports.
	FormatMultiReport(reports []*report.Report) ([]byte, error)
	// FileExtension returns the file extension for this format (e.g., ".csv").
	FileExtension() string
}

// GetFormatter returns a Formatter for the given format string.
// Supported formats: "json", "csv", "markdown", "html", "xlsx".
func GetFormatter(format string) (Formatter, error) {
	switch format {
	case "json":
		return &JSONFormatter{}, nil
	case "csv":
		return &CSVFormatter{}, nil
	case "markdown", "md":
		return &MarkdownFormatter{}, nil
	case "html":
		return &HTMLFormatter{}, nil
	case "xlsx":
		return &XLSXFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %q", format)
	}
}
