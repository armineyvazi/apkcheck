// Package jsonreport writes versioned JSON analysis reports.
package jsonreport

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/armin/apkcheck/pkg/model"
)

// Write encodes the analysis result as indented JSON.
func Write(w io.Writer, r *model.AnalysisResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode json report: %w", err)
	}
	return nil
}

// WriteFile writes JSON to a path.
func WriteFile(path string, r *model.AnalysisResult) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	return Write(f, r)
}
