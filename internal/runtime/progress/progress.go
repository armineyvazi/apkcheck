// Package progress renders plain download and wait status for runtime setup.
// Downloads show byte progress. Boot/install use simple wait lines — never
// dressed up as a package download.
package progress

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
	cCyan   = "\033[36m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Bar is a live download progress renderer (bytes only).
type Bar struct {
	w       io.Writer
	name    string
	mu      sync.Mutex
	color   bool
	frame   int
	started time.Time
}

// NewBar creates a download progress bar writing to w (usually os.Stderr).
func NewBar(w io.Writer, packageName string) *Bar {
	if w == nil {
		w = io.Discard
	}
	return &Bar{
		w:       w,
		name:    packageName,
		color:   isTTY(w),
		started: time.Now(),
	}
}

func (b *Bar) paint(s, code string) string {
	if !b.color {
		return s
	}
	return code + s + cReset
}

// Start prints a download header (spinner bar style — downloads only).
func (b *Bar) Start() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = time.Now()
	fmt.Fprintln(b.w)
	fmt.Fprintf(b.w, "  %s %s\n", b.paint("fetch", cDim), b.paint(b.name, cBold+cCyan))
}

// Update draws a single-line live bar for downloads (bytes).
func (b *Bar) Update(done, total, transferredThisSession int64, elapsed time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.frame = (b.frame + 1) % len(spinnerFrames)
	spin := spinnerFrames[b.frame]

	speed := 0.0
	if elapsed > 0 && transferredThisSession > 0 {
		speed = float64(transferredThisSession) / elapsed.Seconds() / (1024 * 1024)
	}

	var line string
	if total > 0 {
		pct := float64(done) * 100 / float64(total)
		if pct > 100 {
			pct = 100
		}
		bar := renderBar(pct, 28, b.color)
		eta := ""
		remain := total - done
		if speed > 0.05 && remain > 0 {
			secs := float64(remain) / (1024 * 1024) / speed
			eta = "  " + b.paint("eta "+formatETA(secs), cDim)
		}
		line = fmt.Sprintf("  %s %s %s  %s / %s  %s%s",
			b.paint(spin, cCyan),
			bar,
			b.paint(fmt.Sprintf("%5.1f%%", pct), cBold),
			formatBytes(done),
			formatBytes(total),
			b.paint(fmt.Sprintf("%.1f MB/s", speed), cYellow),
			eta,
		)
	} else {
		line = fmt.Sprintf("  %s %s  %s  %s",
			b.paint(spin, cCyan),
			b.paint("downloading...", cDim),
			formatBytes(done),
			b.paint(fmt.Sprintf("%.1f MB/s", speed), cYellow),
		)
	}
	b.rewrite(line)
}

// Success finalizes the download bar.
func (b *Bar) Success(detail string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clearLine()
	msg := detail
	if msg == "" {
		msg = "done"
	}
	fmt.Fprintf(b.w, "  %s %s %s\n",
		b.paint("ok", cGreen),
		b.paint(b.name, cBold),
		b.paint(msg, cDim),
	)
}

// Fail finalizes with an error mark.
func (b *Bar) Fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clearLine()
	fmt.Fprintf(b.w, "  %s %s %v\n",
		b.paint("fail", cRed),
		b.paint(b.name, cBold),
		err,
	)
}

// Info prints a dim side note.
func (b *Bar) Info(msg string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clearLine()
	fmt.Fprintf(b.w, "  %s %s\n", b.paint("-", cDim), b.paint(fmt.Sprintf(msg, args...), cDim))
}

func (b *Bar) rewrite(line string) {
	fmt.Fprint(b.w, "\r\033[K")
	fmt.Fprint(b.w, line)
}

func (b *Bar) clearLine() {
	fmt.Fprint(b.w, "\r\033[K")
}

// Waiter is plain status for boot / install waits (not a download bar).
// Uses an animated spinner so progress is visible; prints a new line every
// few seconds so terminals that ignore \r still show updates.
type Waiter struct {
	w          io.Writer
	name       string
	kind       string
	mu         sync.Mutex
	color      bool
	frame      int
	lastPrint  time.Duration
	printEvery time.Duration
}

// NewWaiter creates a plain wait status printer (boot, install, …).
func NewWaiter(w io.Writer, name, kind string) *Waiter {
	if w == nil {
		w = io.Discard
	}
	if kind == "" {
		kind = "wait"
	}
	return &Waiter{
		w: w, name: name, kind: kind, color: isTTY(w),
		printEvery: 5 * time.Second,
	}
}

// NewTaskBar keeps the old name as an alias for NewWaiter (boot/install).
// Deprecated naming retained for call sites; behavior is Waiter, not a download bar.
func NewTaskBar(w io.Writer, name, kind string) *Waiter {
	return NewWaiter(w, name, kind)
}

func (w *Waiter) paint(s, code string) string {
	if !w.color {
		return s
	}
	return code + s + cReset
}

// Start prints a plain header (no download chrome, no emoji).
func (w *Waiter) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintln(w.w)
	fmt.Fprintf(w.w, "  %s %s\n", w.paint(w.kind, cDim), w.paint(w.name, cBold+cCyan))
	fmt.Fprintf(w.w, "  %s look for the Android Emulator window on your Mac; terminal waits for boot\n",
		w.paint("-", cDim))
}

// UpdateTimed shows animated wait progress. Every printEvery seconds, emits a
// full newline so Cursor/agent terminals (which often hide \r updates) stay readable.
func (w *Waiter) UpdateTimed(elapsed, timeout time.Duration, detail string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if detail == "" {
		detail = "waiting..."
	}
	w.frame = (w.frame + 1) % len(spinnerFrames)
	spin := spinnerFrames[w.frame]
	pct := 0.0
	if timeout > 0 {
		pct = float64(elapsed) * 100 / float64(timeout)
		if pct > 99 {
			pct = 99
		}
		if pct < 0 {
			pct = 0
		}
	}
	bar := renderBar(pct, 20, w.color)
	line := fmt.Sprintf("  %s %s %s  %s / %s  %s",
		w.paint(spin, cCyan),
		bar,
		w.paint(fmt.Sprintf("%4.0f%%", pct), cBold),
		formatDuration(elapsed),
		formatDuration(timeout),
		w.paint(detail, cDim),
	)

	// Always emit a newline periodically so progress is visible even when
	// the terminal does not honor carriage-return in-place updates.
	if elapsed-w.lastPrint >= w.printEvery || w.lastPrint == 0 && elapsed >= w.printEvery {
		fmt.Fprint(w.w, "\r\033[K")
		fmt.Fprintln(w.w, line)
		w.lastPrint = elapsed
		return
	}
	if w.color {
		fmt.Fprint(w.w, "\r\033[K")
		fmt.Fprint(w.w, line)
	}
}

// Success finalizes the wait.
func (w *Waiter) Success(detail string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprint(w.w, "\r\033[K")
	msg := detail
	if msg == "" {
		msg = "done"
	}
	fmt.Fprintf(w.w, "  %s %s %s\n",
		w.paint("ok", cGreen),
		w.paint(w.name, cBold),
		w.paint(msg, cDim),
	)
}

// Fail finalizes with an error.
func (w *Waiter) Fail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprint(w.w, "\r\033[K")
	fmt.Fprintf(w.w, "  %s %s %v\n",
		w.paint("fail", cRed),
		w.paint(w.name, cBold),
		err,
	)
}

// Info prints a dim side note.
func (w *Waiter) Info(msg string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprint(w.w, "\r\033[K")
	fmt.Fprintf(w.w, "  %s %s\n", w.paint("-", cDim), w.paint(fmt.Sprintf(msg, args...), cDim))
}

func renderBar(pct float64, width int, color bool) string {
	if width < 8 {
		width = 8
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if color {
		return cCyan + bar + cReset
	}
	return bar
}

func formatBytes(n int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.0f KB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func formatETA(secs float64) string {
	if secs < 0 {
		secs = 0
	}
	return formatDuration(time.Duration(secs * float64(time.Second)))
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Truncate(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%02dm", h, m)
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

// PackageLabel builds a package id for a system image download.
func PackageLabel(api, tag, abi string) string {
	return fmt.Sprintf("system-images;android-%s;%s;%s", api, tag, abi)
}

// EmulatorLabel builds a plain AVD name for boot wait status.
func EmulatorLabel(avd string) string {
	return avd
}
