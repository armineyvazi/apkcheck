package emulator

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/env"
	"github.com/armin/apkcheck/internal/runtime/progress"
)

// CreateOptions configures AVD creation on macOS.
type CreateOptions struct {
	Name     string // e.g. Pixel_8_API_34
	API      string // e.g. 34
	Tag      string // google_apis | default | google_apis_playstore
	ABI      string // arm64-v8a
	Device   string // pixel_8
	Force    bool
	Progress io.Writer // live status (stderr recommended)
}

var apiFromNameRE = regexp.MustCompile(`(?i)api[_-]?(\d{2,3})`)

// ParseCreateFromName fills API/device defaults from a common AVD name.
func ParseCreateFromName(name string) CreateOptions {
	opt := DefaultCreate(name)
	if m := apiFromNameRE.FindStringSubmatch(name); m != nil {
		opt.API = m[1]
	}
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "pixel_7"):
		opt.Device = "pixel_7"
	case strings.Contains(lower, "pixel_6"):
		opt.Device = "pixel_6"
	case strings.Contains(lower, "pixel_5"):
		opt.Device = "pixel_5"
	case strings.Contains(lower, "pixel_4"):
		opt.Device = "pixel_4"
	case strings.Contains(lower, "pixel"):
		opt.Device = "pixel_8"
	}
	return opt
}

// DefaultCreate returns Apple-Silicon-friendly defaults.
func DefaultCreate(name string) CreateOptions {
	if name == "" {
		name = "Pixel_8_API_34"
	}
	abi := "arm64-v8a"
	if env.Discover().HostArch == "amd64" {
		abi = "x86_64"
	}
	return CreateOptions{
		Name: name, API: "34", Tag: "google_apis", ABI: abi, Device: "pixel_8",
	}
}

// EnsureAVD installs the system image if needed and creates the AVD.
// Uses Google redirector CDN when sdkmanager package URLs 404.
// Shows resume-capable download progress with percentage when size is known.
func (m *Manager) EnsureAVD(ctx context.Context, opt CreateOptions) error {
	if opt.Name == "" {
		opt = DefaultCreate("")
	} else if opt.API == "" {
		parsed := ParseCreateFromName(opt.Name)
		if opt.API == "" {
			opt.API = parsed.API
		}
		if opt.Device == "" {
			opt.Device = parsed.Device
		}
		if opt.Tag == "" {
			opt.Tag = parsed.Tag
		}
		if opt.ABI == "" {
			opt.ABI = parsed.ABI
		}
	}
	if opt.API == "" {
		opt.API = "34"
	}
	if opt.Tag == "" {
		opt.Tag = "google_apis"
	}
	if opt.ABI == "" {
		opt.ABI = DefaultCreate(opt.Name).ABI
	}
	if opt.Device == "" {
		opt.Device = "pixel_8"
	}
	logf := func(format string, args ...any) {
		if opt.Progress != nil {
			fmt.Fprintf(opt.Progress, format+"\n", args...)
		}
	}

	// Ensure JAVA_HOME / ANDROID_HOME for child tools.
	sdk, err := env.Bootstrap()
	if err != nil {
		return err
	}
	m.SDK = sdk
	if m.Emulator == "" {
		m.Emulator = sdk.Emulator
	}
	if m.SDK.Root == "" {
		return fmt.Errorf("ANDROID_HOME / Android SDK not found — brew install --cask android-commandlinetools")
	}
	if m.Emulator == "" {
		return fmt.Errorf("emulator binary missing under %s/emulator\nHint: sdkmanager --install emulator", m.SDK.Root)
	}
	if sdk.JavaHome == "" {
		logf("warning: JDK 17+ not found — avdmanager may fail (brew install openjdk@17)")
	} else {
		logf("using JAVA_HOME=%s", sdk.JavaHome)
	}
	logf("using ANDROID_HOME=%s", m.SDK.Root)

	// Ensure system image first (even when AVD already exists).
	pkg := fmt.Sprintf("system-images;android-%s;%s;%s", opt.API, opt.Tag, opt.ABI)
	imgDir := filepath.Join(m.SDK.Root, "system-images", "android-"+opt.API, opt.Tag, opt.ABI)

	if !systemImageReady(imgDir) {
		logf("Installing platform packages (sdkmanager)…")
		_ = m.sdkInstall(ctx, "platform-tools", "platforms;android-"+opt.API, "emulator")

		logf("System image missing — trying sdkmanager for %s …", pkg)
		sdkCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		err := m.sdkInstall(sdkCtx, pkg)
		cancel()
		if err != nil || !systemImageReady(imgDir) {
			_ = os.RemoveAll(imgDir)
			logf("sdkmanager incomplete — fetching system image (resume supported)…")
			if err := downloadSystemImage(ctx, opt, imgDir, opt.Progress); err != nil {
				return fmt.Errorf("install system image: %w\nHint: check network/VPN access to redirector.gvt1.com", err)
			}
		}
	} else {
		logf("System image already present: %s", imgDir)
	}

	if !systemImageReady(imgDir) {
		return fmt.Errorf("system image still incomplete at %s", imgDir)
	}

	// AVD already exists?
	if !opt.Force {
		avds, _ := m.ListAVDs(ctx)
		for _, a := range avds {
			if a.Name == opt.Name {
				logf("AVD %s already exists", opt.Name)
				return nil
			}
		}
	}

	logf("Creating AVD %s …", opt.Name)
	avdmanager, err := lookBeside(m.SDK.Root, "avdmanager")
	if err != nil {
		return err
	}
	cmd := m.wrapJava(fmt.Sprintf("printf 'no\\n' | %q create avd -n %q -k %q -d %q --force",
		avdmanager, opt.Name, pkg, opt.Device))
	res, err := runner.Run(ctx, "/bin/bash", "-lc", cmd)
	out := ""
	if res != nil {
		out = res.Stdout + res.Stderr
	}
	if err != nil {
		logf("retry without device skin…")
		cmd = m.wrapJava(fmt.Sprintf("printf 'no\\n' | %q create avd -n %q -k %q --force", avdmanager, opt.Name, pkg))
		res, err = runner.Run(ctx, "/bin/bash", "-lc", cmd)
		if res != nil {
			out = res.Stdout + res.Stderr
		}
		if err != nil {
			return fmt.Errorf("avdmanager create failed: %w\n%s", err, out)
		}
	}
	logf("AVD ready: %s", opt.Name)
	return nil
}

func (m *Manager) wrapJava(inner string) string {
	jh := m.SDK.JavaHome
	if jh == "" {
		jh = env.FindJavaHome(17)
	}
	if jh == "" {
		return inner
	}
	return fmt.Sprintf("export JAVA_HOME=%q; export PATH=\"$JAVA_HOME/bin:$PATH\"; export ANDROID_HOME=%q; export ANDROID_SDK_ROOT=%q; %s",
		jh, m.SDK.Root, m.SDK.Root, inner)
}

func (m *Manager) sdkInstall(ctx context.Context, packages ...string) error {
	sdkmanager, err := lookBeside(m.SDK.Root, "sdkmanager")
	if err != nil {
		return err
	}
	args := append([]string{"--install"}, packages...)
	cmd := m.wrapJava(fmt.Sprintf("yes | %q %s", sdkmanager, shellJoin(args)))
	_, err = runner.Run(ctx, "/bin/bash", "-lc", cmd)
	return err
}

func shellJoin(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fmt.Sprintf("%q", a))
	}
	return b.String()
}

func lookBeside(sdkRoot, name string) (string, error) {
	cands := []string{
		filepath.Join(sdkRoot, "cmdline-tools", "latest", "bin", name),
	}
	if p, err := runner.LookPath("", name); err == nil {
		return p, nil
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("%s not found (sdk root %s)", name, sdkRoot)
}

func systemImageReady(dir string) bool {
	for _, p := range []string{
		filepath.Join(dir, "system.img"),
		filepath.Join(dir, "ramdisk.img"),
	} {
		if st, err := os.Stat(p); err == nil && st.Size() > 1024 {
			return true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != ".installer" {
			if systemImageReady(filepath.Join(dir, e.Name())) {
				return true
			}
		}
	}
	return false
}

func downloadSystemImage(ctx context.Context, opt CreateOptions, destDir string, progressOut io.Writer) error {
	urls := []string{
		fmt.Sprintf("https://redirector.gvt1.com/edgedl/android/repository/sys-img/%s/%s-%s_r14.zip", opt.Tag, opt.ABI, opt.API),
		fmt.Sprintf("https://redirector.gvt1.com/edgedl/android/repository/sys-img/%s/%s-%s_r13.zip", opt.Tag, opt.ABI, opt.API),
		fmt.Sprintf("https://redirector.gvt1.com/edgedl/android/repository/sys-img/%s/%s-%s_r12.zip", opt.Tag, opt.ABI, opt.API),
		fmt.Sprintf("https://redirector.gvt1.com/edgedl/android/repository/sys-img/android/%s-%s_r04.zip", opt.ABI, opt.API),
	}
	if opt.Tag == "google_apis" && opt.API == "34" && opt.ABI == "arm64-v8a" {
		urls = append([]string{
			"https://redirector.gvt1.com/edgedl/android/repository/sys-img/google_apis/arm64-v8a-34_r14.zip",
		}, urls...)
	}

	pkgName := progress.PackageLabel(opt.API, opt.Tag, opt.ABI)
	if progressOut == nil {
		progressOut = io.Discard
	}
	var lastErr error
	for i, u := range urls {
		// Per-URL cache file so a partial r14 zip is never resumed onto r13.
		base := filepath.Base(strings.Split(u, "?")[0])
		tmpZip := filepath.Join(os.TempDir(), "apkcheck-"+base)
		bar := progress.NewBar(progressOut, pkgName)
		bar.Start()
		if i > 0 {
			bar.Info("trying mirror %d/%d", i+1, len(urls))
		}
		if err := downloadFile(ctx, u, tmpZip, bar); err != nil {
			bar.Fail(err)
			lastErr = err
			// Keep partial zip so the next run can resume THIS mirror.
			continue
		}
		if !zipValid(tmpZip) {
			lastErr = fmt.Errorf("downloaded zip is corrupt/incomplete")
			bar.Fail(lastErr)
			_ = os.Remove(tmpZip)
			continue
		}
		bar.Info("extracting into SDK…")
		if err := unzipTo(tmpZip, destDir); err != nil {
			bar.Fail(err)
			lastErr = err
			continue
		}
		if !systemImageReady(destDir) {
			_ = flattenOneLevel(destDir)
		}
		if systemImageReady(destDir) {
			_ = writeMinimalPackageXML(destDir, opt)
			bar.Success(fmt.Sprintf("installed (%.0f MB image)", ImageSizeMB(destDir)))
			return nil
		}
		lastErr = fmt.Errorf("zip extracted but system.img not found in %s", destDir)
		bar.Fail(lastErr)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all download mirrors failed")
	}
	return lastErr
}

func zipValid(path string) bool {
	r, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	_ = r.Close()
	return true
}

func downloadFile(ctx context.Context, url, dest string, bar *progress.Bar) error {
	if bar == nil {
		bar = progress.NewBar(io.Discard, filepath.Base(dest))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}

	var start int64
	if st, err := os.Stat(dest); err == nil && st.Size() > 0 {
		if zipValid(dest) {
			bar.Info("using cached complete archive (%s)", formatBytesLocal(st.Size()))
			return nil
		}
		start = st.Size()
		bar.Info("resuming from %s", formatBytesLocal(start))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if start > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
	}
	req.Header.Set("User-Agent", "apkcheck/0.4.5 (Android system-image fetch)")

	client := &http.Client{Timeout: 90 * time.Minute}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		start = 0
	case http.StatusPartialContent:
		// resume OK
	default:
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}

	var total int64 = -1
	if cl := res.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			if res.StatusCode == http.StatusPartialContent {
				total = start + n
			} else {
				total = n
			}
		}
	}
	if cr := res.Header.Get("Content-Range"); strings.Contains(cr, "/") {
		parts := strings.Split(cr, "/")
		if len(parts) == 2 {
			if n, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				total = n
			}
		}
	}

	flag := os.O_CREATE | os.O_WRONLY
	if start > 0 && res.StatusCode == http.StatusPartialContent {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC
		start = 0
	}
	f, err := os.OpenFile(dest, flag, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	written := start
	session := int64(0)
	buf := make([]byte, 256*1024)
	lastPrint := time.Now()
	t0 := time.Now()
	for {
		n, rerr := res.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			written += int64(n)
			session += int64(n)
			if time.Since(lastPrint) >= 200*time.Millisecond {
				bar.Update(written, total, session, time.Since(t0))
				lastPrint = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("interrupted at %s (re-run resumes): %w", formatBytesLocal(written), rerr)
		}
	}
	bar.Update(written, total, session, time.Since(t0))

	if total > 0 && written < total {
		return fmt.Errorf("incomplete: got %s of %s — re-run to resume", formatBytesLocal(written), formatBytesLocal(total))
	}
	if written < 10*1024*1024 {
		return fmt.Errorf("download too small (%s) — likely failed", formatBytesLocal(written))
	}
	return nil
}

func formatBytesLocal(n int64) string {
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
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// progressBar kept for unit tests (simple ASCII form).
func progressBar(pct float64, width int) string {
	if width < 4 {
		width = 4
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func unzipTo(zipPath, destDir string) error {
	_ = os.RemoveAll(destDir)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		name := f.Name
		target := filepath.Join(destDir, name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) &&
			filepath.Clean(target) != filepath.Clean(destDir) {
			return fmt.Errorf("illegal path in zip: %s", name)
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func flattenOneLevel(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var sub string
	for _, e := range entries {
		if e.IsDir() && e.Name() != ".installer" {
			sub = filepath.Join(dir, e.Name())
			break
		}
	}
	if sub == "" || !systemImageReady(sub) {
		return nil
	}
	subs, _ := os.ReadDir(sub)
	for _, e := range subs {
		_ = os.Rename(filepath.Join(sub, e.Name()), filepath.Join(dir, e.Name()))
	}
	return nil
}

func writeMinimalPackageXML(dir string, opt CreateOptions) error {
	srcProps := filepath.Join(dir, "source.properties")
	if _, err := os.Stat(srcProps); err != nil {
		content := fmt.Sprintf("Pkg.Desc=System Image Android API %s\nPkg.Revision=1\nAndroidVersion.ApiLevel=%s\nSystemImage.Abi=%s\nSystemImage.TagId=%s\nSystemImage.TagDisplay=%s\n",
			opt.API, opt.API, opt.ABI, opt.Tag, opt.Tag)
		_ = os.WriteFile(srcProps, []byte(content), 0o644)
	}
	return nil
}

// ImageDir returns the system-images path for an API/tag/abi triple.
func ImageDir(sdkRoot, api, tag, abi string) string {
	return filepath.Join(sdkRoot, "system-images", "android-"+api, tag, abi)
}

// ImageReady reports whether a usable system.img exists under dir.
func ImageReady(dir string) bool { return systemImageReady(dir) }

// ImageSizeMB returns approximate system.img size in MiB (0 if missing).
func ImageSizeMB(dir string) float64 {
	st, err := os.Stat(filepath.Join(dir, "system.img"))
	if err != nil {
		return 0
	}
	return float64(st.Size()) / (1024 * 1024)
}
