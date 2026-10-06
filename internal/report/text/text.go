// Package text renders terminal reports.
package text

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/armin/apkcheck/pkg/model"
)

// WriteReport writes a human-readable analysis report.
func WriteReport(w io.Writer, r *model.AnalysisResult) error {
	fmt.Fprintf(w, "APKCheck v%s\n\n", r.ToolVersion)
	fmt.Fprintf(w, "APK: %s\n", r.APK.Path)
	fmt.Fprintf(w, "SHA-256: %s\n", r.APK.SHA256)
	if r.APK.Package != "" {
		fmt.Fprintf(w, "Package: %s\n", r.APK.Package)
	}
	if r.APK.VersionName != "" {
		fmt.Fprintf(w, "Version: %s (%d)\n", r.APK.VersionName, r.APK.VersionCode)
	}
	fmt.Fprintf(w, "minSdk=%d targetSdk=%d DEX=%d native_libs=%d\n\n",
		r.APK.MinSDK, r.APK.TargetSDK, r.APK.DEXCount, len(r.APK.NativeLibs))

	fmt.Fprintf(w, "Methods analyzed: %d", r.Summary.MethodsAnalyzed)
	if r.Summary.SmaliMethodsTotal > 0 {
		fmt.Fprintf(w, "  (smali total: %d)", r.Summary.SmaliMethodsTotal)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Consistent:             %d\n", r.Summary.MethodsConsistent)
	fmt.Fprintf(w, "  Partially consistent:   %d\n", r.Summary.MethodsPartial)
	fmt.Fprintf(w, "  Disagreement:           %d\n", r.Summary.MethodsDisagreement)
	fmt.Fprintf(w, "  Unresolved:             %d\n", r.Summary.MethodsUnresolved)
	fmt.Fprintf(w, "  Security-relevant:      %d\n", r.Summary.SecurityRelevant)
	if r.Summary.SkippedFramework > 0 || r.Summary.SkippedSynthetic > 0 || r.Summary.SkippedEmpty > 0 {
		fmt.Fprintf(w, "  Skipped framework:      %d\n", r.Summary.SkippedFramework)
		fmt.Fprintf(w, "  Skipped synthetic:      %d\n", r.Summary.SkippedSynthetic)
		fmt.Fprintf(w, "  Skipped empty:          %d\n", r.Summary.SkippedEmpty)
	}
	fmt.Fprintln(w)

	if r.Runtime != nil {
		fmt.Fprintln(w, "Runtime:")
		fmt.Fprintf(w, "  session: %s\n", r.Runtime.SessionID)
		fmt.Fprintf(w, "  type: %s\n", r.Runtime.Type)
		if r.Runtime.AVD != "" {
			fmt.Fprintf(w, "  AVD: %s\n", r.Runtime.AVD)
		}
		if r.Runtime.Device != "" {
			fmt.Fprintf(w, "  device: %s (%s)\n", r.Runtime.Device, r.Runtime.DeviceID)
		}
		if r.Runtime.Android != "" {
			fmt.Fprintf(w, "  Android: %s (API %s) %s\n", r.Runtime.Android, r.Runtime.API, r.Runtime.Architecture)
		}
		fmt.Fprintf(w, "  crashes=%d permissions=%d network=%d timeline=%d correlations=%d\n",
			r.Runtime.Crashes, r.Runtime.Permissions, r.Runtime.Network, r.Runtime.Timeline, r.Runtime.Correlations)
		if r.Runtime.SessionJSON != "" {
			fmt.Fprintf(w, "  session: %s\n", r.Runtime.SessionJSON)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Most important findings:")
	shown := 0
	for _, m := range r.Methods {
		if m.Status != model.ConfidenceDisagreement && m.Status != model.ConfidencePartiallyConsistent {
			continue
		}
		fmt.Fprintf(w, "\n⚠ %s\n  Status: %s\n  %s\n", m.Ref.String(), m.Status, m.Verdict)
		for _, iss := range m.Issues {
			fmt.Fprintf(w, "  - [%s/%s] %s\n", iss.Severity, iss.Type, iss.Message)
		}
		shown++
		if shown >= 15 {
			break
		}
	}
	if shown == 0 {
		fmt.Fprintln(w, "  (no major disagreements in analyzed set)")
	}

	fmt.Fprintln(w, "\nNotes:")
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  • %s\n", n)
	}
	fmt.Fprintln(w, "\nLimitations:")
	for _, n := range r.Limitations {
		fmt.Fprintf(w, "  • %s\n", n)
	}
	return nil
}

// WriteMethodDetail writes a detailed single-method report.
func WriteMethodDetail(w io.Writer, m model.MethodResult) error {
	fmt.Fprintf(w, "┌%s┐\n", strings.Repeat("─", 45))
	fmt.Fprintf(w, "│ Method: %-36s │\n", truncate(m.Ref.Class+"."+m.Ref.Name+"()", 36))
	fmt.Fprintf(w, "├%s┤\n", strings.Repeat("─", 45))
	if m.Smali != nil {
		fmt.Fprintf(w, "│ Smali      ✓ source of truth                 │\n")
	}
	order := []string{"jadx", "cfr", "fernflower"}
	for _, name := range order {
		d, ok := m.Decompilers[name]
		if !ok {
			continue
		}
		mark := statusMark(d.Status)
		msg := string(d.Status)
		if len(d.Issues) > 0 {
			msg = d.Issues[0].Message
		}
		line := fmt.Sprintf("%-11s %s %s", strings.ToUpper(name), mark, msg)
		fmt.Fprintf(w, "│ %-43s │\n", truncate(line, 43))
	}
	fmt.Fprintf(w, "└%s┘\n\n", strings.Repeat("─", 45))

	if m.Smali != nil {
		fmt.Fprintln(w, "[DEX/Smali]")
		fmt.Fprintf(w, "  Instructions: %d\n", m.Smali.Instructions)
		fmt.Fprintf(w, "  Basic blocks: %d\n", m.Smali.BasicBlocks)
		fmt.Fprintf(w, "  Branches:     %d\n", m.Smali.Branches)
		fmt.Fprintf(w, "  Calls:        %d\n", m.Smali.Calls)
		fmt.Fprintf(w, "  Exceptions:   %d\n\n", m.Smali.Exceptions)
	}

	for name, d := range m.Decompilers {
		fmt.Fprintf(w, "[%s]\n", strings.ToUpper(name))
		fmt.Fprintf(w, "  Status: %s\n", d.Status)
		for _, iss := range d.Issues {
			fmt.Fprintf(w, "  %s %s\n", issueMark(iss.Severity), iss.Message)
			if iss.Evidence != "" {
				fmt.Fprintf(w, "    evidence: %s\n", iss.Evidence)
			}
		}
		if d.Note != "" {
			fmt.Fprintf(w, "  note: %s\n", d.Note)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "[VERDICT]")
	fmt.Fprintf(w, "  Overall: %s\n", m.Status)
	fmt.Fprintf(w, "  %s\n", m.Verdict)
	return nil
}

// WriteDiffTable writes a compact methods table.
func WriteDiffTable(w io.Writer, methods []model.MethodResult, limit int) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCLASS\tMETHOD\tSECURITY\tISSUES")
	n := 0
	for _, m := range methods {
		if limit > 0 && n >= limit {
			break
		}
		sec := ""
		if m.SecurityRelevant {
			sec = strings.Join(m.SecurityTags, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n",
			m.Status, m.Ref.Class, m.Ref.Name, sec, len(m.Issues))
		n++
	}
	return tw.Flush()
}

// WriteDoctor writes doctor output.
func WriteDoctor(w io.Writer, r *model.DoctorReport) error {
	fmt.Fprintln(w, "apkcheck doctor")
	fmt.Fprintln(w)
	for _, t := range r.Tools {
		mark := "✗"
		if t.Available {
			mark = "✓"
		} else if !t.Required {
			mark = "⚠"
		}
		ver := t.Version
		if !t.Available {
			if !t.Required {
				ver = "not installed"
			} else {
				ver = t.Error
			}
		}
		fmt.Fprintf(w, "%-12s %s %s\n", t.Name, mark, ver)
	}
	fmt.Fprintln(w)
	if r.OK {
		fmt.Fprintln(w, "Required tools: OK")
	} else {
		fmt.Fprintln(w, "Required tools: MISSING — install JADX, Apktool, and Java")
	}
	return nil
}

func statusMark(c model.Confidence) string {
	switch c {
	case model.ConfidenceConsistent:
		return "✓"
	case model.ConfidencePartiallyConsistent:
		return "⚠"
	case model.ConfidenceDisagreement:
		return "✗"
	default:
		return "?"
	}
}

func issueMark(s model.Severity) string {
	switch s {
	case model.SeverityHigh, model.SeverityCritical:
		return "✗"
	case model.SeverityMedium:
		return "⚠"
	default:
		return "•"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
