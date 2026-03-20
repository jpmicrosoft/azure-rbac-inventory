package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jpmicrosoft/azure-rbac-inventory/internal/report"
)

// extensionToFormat maps file extensions to formatter format strings.
var extensionToFormat = map[string]string{
	".json": "json",
	".csv":  "csv",
	".md":   "markdown",
	".html": "html",
	".xlsx": "xlsx",
}

// ExportFile writes a report to a file, auto-detecting format from the
// file extension. Supported extensions: .json, .csv, .md, .html, .xlsx.
func ExportFile(rpt *report.Report, filePath string) error {
	format, err := formatFromPath(filePath)
	if err != nil {
		return err
	}

	f, err := GetFormatter(format)
	if err != nil {
		return err
	}

	data, err := f.FormatReport(rpt)
	if err != nil {
		return fmt.Errorf("failed to format report: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nResults exported to: %s\n", filePath)
	return nil
}

// ExportMultiFile writes multiple reports to a file, auto-detecting
// format from the file extension.
func ExportMultiFile(reports []*report.Report, filePath string) error {
	format, err := formatFromPath(filePath)
	if err != nil {
		return err
	}

	f, err := GetFormatter(format)
	if err != nil {
		return err
	}

	data, err := f.FormatMultiReport(reports)
	if err != nil {
		return fmt.Errorf("failed to format reports: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nResults exported to: %s\n", filePath)
	return nil
}

// formatFromPath extracts the file extension and maps it to a format string.
func formatFromPath(filePath string) (string, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	format, ok := extensionToFormat[ext]
	if !ok {
		return "", fmt.Errorf("unsupported file extension: %q", ext)
	}
	return format, nil
}
