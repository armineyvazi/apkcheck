// Package status prints friendly runtime progress for humans and agents.
package status

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	cReset  = "\033[0m"
	cDim    = "\033[2m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
	cBold   = "\033[1m"
)

// Printer writes phase-oriented status lines to stderr-style writers.
type Printer struct {
	w     io.Writer
	mu    sync.Mutex
	t0    time.Time
	step  int
	color bool
}

func New(w io.Writer) *Printer {
	if w == nil {
		w = io.Discard
	}
	return &Printer{w: w, t0: time.Now(), color: isTTY(w)}
}

func (p *Printer) paint(s, code string) string {
	if !p.color {
		return s
	}
	return code + s + cReset
}

func (p *Printer) Banner(apk, mode, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintln(p.w)
	fmt.Fprintln(p.w, p.paint("┌─ apkcheck runtime ────────────────────────────────────────", cCyan))
	fmt.Fprintf(p.w, "│ APK    %s\n", truncate(apk, 48))
	fmt.Fprintf(p.w, "│ Mode   %s\n", p.paint(mode, cBold))
	if target != "" {
		fmt.Fprintf(p.w, "│ Target %s\n", p.paint(target, cBold+cCyan))
	}
	fmt.Fprintln(p.w, p.paint("└───────────────────────────────────────────────────────────", cCyan))
	fmt.Fprintln(p.w)
}

func (p *Printer) Phase(title string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.step++
	fmt.Fprintf(p.w, "\n%s %s\n", p.paint(fmt.Sprintf("▸ %d.", p.step), cCyan), p.paint(title, cBold))
}

func (p *Printer) OK(msg string, args ...any) {
	p.line(p.paint("ok", cGreen), msg, args...)
}

func (p *Printer) Info(msg string, args ...any) {
	p.line(p.paint("-", cDim), msg, args...)
}

func (p *Printer) Warn(msg string, args ...any) {
	p.line(p.paint("!", cYellow), msg, args...)
}

func (p *Printer) Fail(msg string, args ...any) {
	p.line(p.paint("fail", cRed), msg, args...)
}

func (p *Printer) Working(msg string, args ...any) {
	p.line(p.paint("...", cCyan), msg, args...)
}

func (p *Printer) Progress(msg string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	elapsed := time.Since(p.t0).Truncate(time.Second)
	line := fmt.Sprintf(msg, args...)
	fmt.Fprintf(p.w, "\r  … %s  (%s)   ", line, elapsed)
}

func (p *Printer) ProgressDone() {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintln(p.w)
}

func (p *Printer) line(mark, msg string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  %s %s\n", mark, fmt.Sprintf(msg, args...))
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n+1:]
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
