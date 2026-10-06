package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/env"
)

const HarnessPackage = "com.apkcheck.testharness"

// harnessRev matches testdata/lab/harness/.apkcheck-harness-rev — bump when scaffold changes.
const harnessRev = "3"

// EnsureHarness installs the authorized lab test harness APK if present under workspace/harness.
// The harness is an explicit, visible test aid — not stealth malware.
func EnsureHarness(ctx context.Context, workspace string, client *adb.Client, serial string) (string, error) {
	apk := filepath.Join(workspace, "harness", "testharness-signed.apk")
	if _, err := os.Stat(apk); err != nil {
		proj := filepath.Join(workspace, "harness", "project")
		if st, err2 := os.Stat(proj); err2 == nil && st.IsDir() {
			if err := buildHarness(ctx, workspace); err != nil {
				return "", fmt.Errorf("harness APK missing and build failed: %w (run: apkcheck lab security harness seed && apkcheck lab security harness build)", err)
			}
		} else {
			return "harness APK not installed — run: apkcheck lab security harness seed && apkcheck lab security harness build. Host-side adb intents still work for many probes.", nil
		}
	}
	if client == nil || serial == "" {
		return "harness APK present at " + apk + " (device not connected — install skipped)", nil
	}
	res, err := client.SerialRun(ctx, serial, "install", "-r", "-t", apk)
	out := ""
	if res != nil {
		out = res.Stdout + res.Stderr
	}
	if err != nil {
		return out, fmt.Errorf("install harness: %w\n%s", err, out)
	}
	return "installed " + HarnessPackage + " (authorized test harness)", nil
}

func buildHarness(ctx context.Context, workspace string) error {
	proj := filepath.Join(workspace, "harness", "project")
	out := filepath.Join(workspace, "harness", "testharness-unsigned.apk")
	signed := filepath.Join(workspace, "harness", "testharness-signed.apk")
	_ = os.MkdirAll(filepath.Dir(signed), 0o750)

	if err := ensureApktoolFramework(ctx); err != nil {
		return fmt.Errorf("apktool framework: %w", err)
	}

	apktool, err := exec.LookPath("apktool")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, apktool, "b", "-f", "-o", out, proj)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apktool build: %w\n%s\nHint: re-seed scaffold (apkcheck lab security harness seed --force) — project must be an apktool-decoded tree with resourcesInfo, not a hand-written stub", err, b)
	}

	ks := filepath.Join(workspace, "certs", "apkcheck-debug.keystore")
	if _, err := os.Stat(ks); err != nil {
		return fmt.Errorf("debug keystore missing — run a lab sign once first: %s", ks)
	}
	if apksigner := findOnPathOrBuildTools("apksigner"); apksigner != "" {
		cmd := exec.CommandContext(ctx, apksigner, "sign", "--ks", ks, "--ks-pass", "pass:android", "--key-pass", "pass:android", "--out", signed, out)
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("apksigner: %w\n%s", err, b)
		}
		return nil
	}
	if err := copyFileSimple(out, signed); err != nil {
		return err
	}
	jarsigner, err := exec.LookPath("jarsigner")
	if err != nil {
		return fmt.Errorf("no apksigner/jarsigner")
	}
	cmd = exec.CommandContext(ctx, jarsigner, "-keystore", ks, "-storepass", "android", "-keypass", "android", signed, "apkcheck")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("jarsigner: %w\n%s", err, b)
	}
	return nil
}

// ensureApktoolFramework installs android.jar as apktool framework 1 if missing.
func ensureApktoolFramework(ctx context.Context) error {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "Library", "apktool", "framework", "1.apk"),
		filepath.Join(home, ".local", "share", "apktool", "framework", "1.apk"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.Size() > 0 {
			return nil
		}
	}
	jar := findAndroidJar()
	if jar == "" {
		return fmt.Errorf("android.jar not found — install platforms;android-34 (sdkmanager) so apktool aapt2 can link manifests")
	}
	apktool, err := exec.LookPath("apktool")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, apktool, "if", jar)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apktool if: %w\n%s", err, b)
	}
	return nil
}

func findAndroidJar() string {
	roots := []string{
		os.Getenv("ANDROID_HOME"),
		os.Getenv("ANDROID_SDK_ROOT"),
		"/opt/homebrew/share/android-commandlinetools",
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		platforms := filepath.Join(root, "platforms")
		entries, err := os.ReadDir(platforms)
		if err != nil {
			continue
		}
		var best string
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "android-") {
				continue
			}
			cand := filepath.Join(platforms, e.Name(), "android.jar")
			if st, err := os.Stat(cand); err == nil && st.Size() > 0 {
				best = cand
			}
		}
		if best != "" {
			return best
		}
	}
	return ""
}

func findOnPathOrBuildTools(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, root := range []string{os.Getenv("ANDROID_HOME"), os.Getenv("ANDROID_SDK_ROOT"), "/opt/homebrew/share/android-commandlinetools"} {
		if root == "" {
			continue
		}
		bt := filepath.Join(root, "build-tools")
		entries, _ := os.ReadDir(bt)
		var best string
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			cand := filepath.Join(bt, e.Name(), name)
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				best = cand
			}
		}
		if best != "" {
			return best
		}
	}
	return ""
}

func copyFileSimple(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o640)
}

// HarnessStatus reports whether harness sources/APK exist.
func HarnessStatus(workspace string) map[string]any {
	apk := filepath.Join(workspace, "harness", "testharness-signed.apk")
	proj := filepath.Join(workspace, "harness", "project")
	_, apkErr := os.Stat(apk)
	_, projErr := os.Stat(proj)
	rev := readHarnessRev(proj)
	return map[string]any{
		"package":          HarnessPackage,
		"apk_path":         apk,
		"apk_present":      apkErr == nil,
		"project_present":  projErr == nil,
		"scaffold_rev":     rev,
		"expected_rev":     harnessRev,
		"scaffold_current": rev == harnessRev,
		"note":             "Explicit authorized test harness for IPC probes. Not stealth. Host adb am intents remain primary.",
		"seed_hint":        "apkcheck lab security harness seed [--force] && apkcheck lab security harness build",
	}
}

func readHarnessRev(proj string) string {
	b, err := os.ReadFile(filepath.Join(proj, ".apkcheck-harness-rev"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SeedHarnessProject copies the bundled harness project into the workspace if missing.
func SeedHarnessProject(workspace, repoHarnessDir string) error {
	return SeedHarnessProjectOpts(workspace, repoHarnessDir, false)
}

// SeedHarnessProjectOpts copies the scaffold; force replaces an outdated/broken project.
func SeedHarnessProjectOpts(workspace, repoHarnessDir string, force bool) error {
	dest := filepath.Join(workspace, "harness", "project")
	if repoHarnessDir == "" {
		return fmt.Errorf("harness source dir required")
	}
	if st, err := os.Stat(dest); err == nil && st.IsDir() {
		cur := readHarnessRev(dest)
		if !force && cur == harnessRev {
			return nil
		}
		_ = os.RemoveAll(dest)
	}
	if err := copyDir(repoHarnessDir, dest); err != nil {
		return err
	}
	// Ensure stamp present even if source lacked it
	_ = os.WriteFile(filepath.Join(dest, ".apkcheck-harness-rev"), []byte(harnessRev+"\n"), 0o640)
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o640)
	})
}

// ProbeIntent is a documented, non-stealth adb intent send for authorized testing.
func ProbeIntent(ctx context.Context, client *adb.Client, serial, component string, extras map[string]string) (string, error) {
	args := []string{"am", "start", "-n", component, "--es", "apkcheck_harness", "1"}
	for k, v := range extras {
		args = append(args, "--es", k, v)
	}
	out, err := client.Shell(ctx, serial, args...)
	return strings.TrimSpace(out), err
}

// ResolveDeviceSerial picks an adb serial from --device-id or --emulator (AVD name), else first device.
func ResolveDeviceSerial(ctx context.Context, deviceID, emulatorAVD string) string {
	if strings.TrimSpace(deviceID) != "" {
		return strings.TrimSpace(deviceID)
	}
	sdk := env.Discover()
	c, err := adb.New(sdk)
	if err != nil {
		return ""
	}
	res, err := c.Run(ctx, "devices", "-l")
	if err != nil || res == nil {
		return DiscoverDefaultSerial(ctx)
	}
	avdWant := strings.TrimSpace(emulatorAVD)
	var first string
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "device" {
			continue
		}
		serial := f[0]
		if first == "" {
			first = serial
		}
		if avdWant == "" {
			continue
		}
		// devices -l may include product:/model:/device: — AVD name often via emu avd name
		joined := strings.ToLower(line)
		if strings.Contains(joined, strings.ToLower(avdWant)) {
			return serial
		}
	}
	if avdWant != "" {
		// Query each emulator for AVD name
		for _, line := range strings.Split(res.Stdout, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) < 2 || f[1] != "device" || !strings.HasPrefix(f[0], "emulator-") {
				continue
			}
			out, err := c.Shell(ctx, f[0], "getprop", "ro.kernel.qemu.avd_name")
			if err == nil && strings.TrimSpace(out) == avdWant {
				return f[0]
			}
			out2, err2 := c.Shell(ctx, f[0], "getprop", "ro.boot.qemu.avd_name")
			if err2 == nil && strings.TrimSpace(out2) == avdWant {
				return f[0]
			}
		}
	}
	if first != "" {
		return first
	}
	return DiscoverDefaultSerial(ctx)
}
