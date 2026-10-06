package security

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExportFormat for evidence bundles.
type ExportFormat string

const (
	ExportJSON ExportFormat = "json"
	ExportMD   ExportFormat = "markdown"
	ExportHTML ExportFormat = "html"
	ExportZIP  ExportFormat = "zip"
)

// ExportObservation writes observation (+ linked evidence paths) to outPath.
func ExportObservation(o *Observation, format ExportFormat, outPath string) error {
	if o == nil {
		return fmt.Errorf("nil observation")
	}
	switch format {
	case ExportJSON, "":
		data, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(outPath, data, 0o640)
	case ExportMD:
		return os.WriteFile(outPath, []byte(observationMarkdown(o)), 0o640)
	case ExportHTML:
		return os.WriteFile(outPath, []byte(observationHTML(o)), 0o640)
	case ExportZIP:
		return zipObservation(o, outPath)
	default:
		return fmt.Errorf("unknown format %s", format)
	}
}

func observationMarkdown(o *Observation) string {
	var b strings.Builder
	b.WriteString("# Observation (not an automatic vulnerability claim)\n\n")
	fmt.Fprintf(&b, "- **ID:** %s\n- **Title:** %s\n- **Severity:** %s\n- **Package:** %s\n- **Component:** %s\n- **Artifact:** %s\n- **Template:** %s\n- **Runtime:** %s\n- **Created:** %s\n\n",
		o.ID, o.Title, o.Severity, o.Package, o.Component, o.ArtifactID, o.TemplateID, o.Runtime, o.CreatedAt.Format(time.RFC3339))
	b.WriteString("## Summary\n\n")
	b.WriteString(o.Summary + "\n\n")
	if len(o.Reproduction) > 0 {
		b.WriteString("## Reproduction\n\n")
		for _, r := range o.Reproduction {
			fmt.Fprintf(&b, "1. %s\n", r)
		}
		b.WriteString("\n")
	}
	if len(o.Evidence) > 0 {
		b.WriteString("## Evidence\n\n")
		for _, e := range o.Evidence {
			fmt.Fprintf(&b, "- **%s** %s `%s`\n", e.Kind, e.Label, e.Path)
			if e.Snippet != "" {
				b.WriteString("```\n" + e.Snippet + "\n```\n")
			}
		}
		b.WriteString("\n")
	}
	if o.TesterNotes != "" {
		b.WriteString("## Tester notes\n\n" + o.TesterNotes + "\n")
	}
	b.WriteString("\n---\nAuthorized testing only. Review evidence before any disclosure.\n")
	return b.String()
}

func observationHTML(o *Observation) string {
	md := observationMarkdown(o)
	escaped := strings.ReplaceAll(md, "&", "&amp;")
	escaped = strings.ReplaceAll(escaped, "<", "&lt;")
	return "<!DOCTYPE html><html><head><meta charset=utf-8><title>Observation " + o.ID +
		"</title><style>body{font-family:system-ui;background:#0b1220;color:#e8eef7;padding:2rem;max-width:900px;margin:auto}pre{white-space:pre-wrap}</style></head><body><pre>" +
		escaped + "</pre></body></html>"
}

func zipObservation(o *Observation, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	w, err := zw.Create("observation.json")
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(o, "", "  ")
	if _, err := w.Write(data); err != nil {
		return err
	}
	w2, err := zw.Create("observation.md")
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w2, observationMarkdown(o)); err != nil {
		return err
	}
	for i, e := range o.Evidence {
		if e.Path == "" {
			continue
		}
		st, err := os.Stat(e.Path)
		if err != nil {
			continue
		}
		if st.IsDir() {
			_ = filepath.Walk(e.Path, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(e.Path, path)
				return addFileToZip(zw, path, filepath.Join("evidence", fmt.Sprintf("%d", i), rel))
			})
			continue
		}
		_ = addFileToZip(zw, e.Path, filepath.Join("evidence", filepath.Base(e.Path)))
	}
	return nil
}

func addFileToZip(zw *zip.Writer, src, name string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, in)
	return err
}

// MatrixResult compares scenario outcomes across artifacts.
type MatrixResult struct {
	ArtifactIDs []string            `json:"artifact_ids"`
	TemplateIDs []string            `json:"template_ids"`
	Cells       map[string]string   `json:"cells"` // key: template|artifact → ok|fail|skip
	Reports     map[string]string   `json:"reports,omitempty"`
}

// BuildMatrix runs templates against multiple artifacts (sequential).
func (e *Engine) BuildMatrix(ctx context.Context, artifactIDs, templateIDs []string, serial string) (*MatrixResult, error) {
	m := &MatrixResult{
		ArtifactIDs: artifactIDs, TemplateIDs: templateIDs,
		Cells: map[string]string{}, Reports: map[string]string{},
	}
	for _, aid := range artifactIDs {
		for _, tid := range templateIDs {
			key := tid + "|" + aid
			r, err := e.Run(ctx, RunOptions{ArtifactID: aid, TemplateID: tid, Serial: serial})
			if r != nil {
				m.Reports[key] = r.ID
				if r.OK {
					m.Cells[key] = "ok"
				} else {
					m.Cells[key] = "fail"
				}
			} else if err != nil {
				m.Cells[key] = "fail"
			} else {
				m.Cells[key] = "skip"
			}
		}
	}
	return m, nil
}
