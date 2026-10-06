// Package logcat captures and parses Android logcat evidence.
package logcat

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Crash is a detected runtime failure.
type Crash struct {
	Kind       string   `json:"kind"` // java | native | anr | process_death
	Summary    string   `json:"summary"`
	StackTrace string   `json:"stack_trace"`
	Class      string   `json:"class,omitempty"`
	Method     string   `json:"method,omitempty"`
	Frames     []Frame  `json:"frames,omitempty"`
	RawLines   []string `json:"raw_lines,omitempty"`
}

// Frame is one stack frame.
type Frame struct {
	Class  string `json:"class,omitempty"`
	Method string `json:"method,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Raw    string `json:"raw"`
}

var (
	frameRe = regexp.MustCompile(`at\s+([\w.$]+)\.([\w$<>]+)\(([^:)]+)(?::(\d+))?\)`)
)

// Capture dumps logcat after clearing, waiting for duration while the app runs.
func Capture(ctx context.Context, client *adb.Client, serial, outPath string, wait time.Duration) (string, error) {
	_, _ = client.SerialRun(ctx, serial, "logcat", "-c")
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
	}
	res, err := client.SerialRun(ctx, serial, "logcat", "-d", "-v", "threadtime")
	raw := ""
	if res != nil {
		raw = res.Stdout
		if raw == "" {
			raw = res.Stderr
		}
	}
	if outPath != "" {
		_ = os.WriteFile(outPath, []byte(raw), 0o640)
	}
	if err != nil {
		return raw, err
	}
	return raw, nil
}

// FilterApp keeps lines related to package / AndroidRuntime / crashes.
func FilterApp(raw, pkg string) string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if pkg != "" && strings.Contains(line, pkg) {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		if strings.Contains(line, "AndroidRuntime") ||
			strings.Contains(line, "DEBUG") && strings.Contains(line, "fatal") ||
			strings.Contains(line, "ActivityManager") && (strings.Contains(line, "ANR") || strings.Contains(line, "Process")) ||
			strings.Contains(line, "libc") && strings.Contains(line, "Fatal") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// DetectCrashes extracts crash evidence from raw logcat.
func DetectCrashes(raw string) []Crash {
	var crashes []Crash
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case strings.Contains(line, "FATAL EXCEPTION"):
			c := Crash{Kind: "java", Summary: strings.TrimSpace(line)}
			var rawLines []string
			rawLines = append(rawLines, line)
			for j := i + 1; j < len(lines) && j < i+80; j++ {
				l := lines[j]
				rawLines = append(rawLines, l)
				if fr := parseFrame(l); fr != nil {
					c.Frames = append(c.Frames, *fr)
					if c.Class == "" && !strings.HasPrefix(fr.Class, "android.") && !strings.HasPrefix(fr.Class, "java.") {
						c.Class = fr.Class
						c.Method = fr.Method
					}
				}
				if strings.Contains(l, "FATAL EXCEPTION") && j > i {
					break
				}
				if strings.TrimSpace(l) == "" && len(c.Frames) > 0 {
					break
				}
			}
			c.RawLines = rawLines
			c.StackTrace = strings.Join(rawLines, "\n")
			crashes = append(crashes, c)
		case strings.Contains(line, "ANR in") || strings.Contains(line, "Application Not Responding"):
			crashes = append(crashes, Crash{Kind: "anr", Summary: strings.TrimSpace(line), StackTrace: line, RawLines: []string{line}})
		case strings.Contains(line, "Fatal signal") || strings.Contains(line, "SIGSEGV") || strings.Contains(line, "SIGABRT"):
			crashes = append(crashes, Crash{Kind: "native", Summary: strings.TrimSpace(line), StackTrace: line, RawLines: []string{line}})
		}
	}
	return crashes
}

func parseFrame(line string) *Frame {
	m := frameRe.FindStringSubmatch(line)
	if len(m) < 4 {
		return nil
	}
	fr := &Frame{Class: m[1], Method: m[2], File: m[3], Raw: strings.TrimSpace(line)}
	if len(m) >= 5 && m[4] != "" {
		fmtSscanf(m[4], &fr.Line)
	}
	return fr
}

func fmtSscanf(s string, n *int) {
	v := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		v = v*10 + int(r-'0')
	}
	*n = v
}
