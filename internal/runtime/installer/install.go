// Package installer installs APKs via adb and records evidence.
package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Result is installation evidence.
type Result struct {
	Success   bool     `json:"success"`
	Output    string   `json:"output"`
	Error     string   `json:"error,omitempty"`
	Package   string   `json:"package,omitempty"`
	APKSHA256 string   `json:"apk_sha256"`
	APKPath   string   `json:"apk_path"`
	Reinstall bool     `json:"reinstall"`
	SplitNote string   `json:"split_note,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Meta is pre-install APK metadata for reports.
type Meta struct {
	SHA256      string   `json:"sha256"`
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	Package     string   `json:"package,omitempty"`
	VersionName string   `json:"version_name,omitempty"`
	VersionCode int64    `json:"version_code,omitempty"`
	MinSDK      int      `json:"min_sdk,omitempty"`
	TargetSDK   int      `json:"target_sdk,omitempty"`
	ABIs        []string `json:"abis,omitempty"`
	DEXCount    int      `json:"dex_count"`
}

// InspectAPK collects install-time metadata.
func InspectAPK(apkPath string) (*Meta, error) {
	info, err := apk.Inspect(apkPath)
	if err != nil {
		return nil, err
	}
	meta := &Meta{
		SHA256: info.SHA256, Path: info.Path, Size: info.Size,
		Package: info.Package, VersionName: info.VersionName, VersionCode: info.VersionCode,
		MinSDK: info.MinSDK, TargetSDK: info.TargetSDK, ABIs: info.ABIs, DEXCount: info.DEXCount,
	}
	if meta.Package == "" {
		if pkg := packageFromBadging(apkPath); pkg != "" {
			meta.Package = pkg
		}
	}
	return meta, nil
}

func packageFromBadging(apkPath string) string {
	aapt := ""
	if p, err := execLookBuildTool("aapt"); err == nil {
		aapt = p
	}
	if aapt == "" {
		return ""
	}
	cmd := exec.Command(aapt, "dump", "badging", apkPath)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	// package: name='com.example.app'
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		if i := strings.Index(line, "name='"); i >= 0 {
			rest := line[i+6:]
			if j := strings.Index(rest, "'"); j >= 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

func execLookBuildTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
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
			return best, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

// DetectSplitFormat notes multi-apk package formats that cannot be installed as a single APK.
func DetectSplitFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".apks", ".xapk", ".apkm":
		return fmt.Sprintf("%s bundle detected — refuse single-file adb install (splits required; use extracted base+config APKs or bundletool)", ext)
	default:
		return ""
	}
}

// Install pushes the APK to the device.
// When reinstall is true and the device rejects the APK due to a signing-key
// mismatch (INSTALL_FAILED_UPDATE_INCOMPATIBLE), the existing package is
// uninstalled and the install is retried once — required when switching between
// Play-signed originals and Lab-signed rebuilds.
func Install(ctx context.Context, client *adb.Client, serial, apkPath string, reinstall bool) (*Result, error) {
	if note := DetectSplitFormat(apkPath); note != "" {
		return &Result{Success: false, Error: note, APKPath: apkPath, SplitNote: note}, fmt.Errorf("%s", note)
	}
	meta, err := InspectAPK(apkPath)
	if err != nil {
		return nil, err
	}
	res := &Result{
		APKSHA256: meta.SHA256,
		APKPath:   apkPath,
		Reinstall: reinstall,
		Package:   meta.Package,
		SplitNote: DetectSplitFormat(apkPath),
	}
	if res.SplitNote != "" {
		res.Warnings = append(res.Warnings, res.SplitNote)
	}

	tryInstall := func() error {
		args := []string{"install"}
		if reinstall {
			args = append(args, "-r")
		}
		args = append(args, "-t", apkPath)
		out, err := client.SerialRun(ctx, serial, args...)
		if out != nil {
			res.Output = strings.TrimSpace(out.Stdout + "\n" + out.Stderr)
		}
		if err != nil {
			res.Success = false
			res.Error = err.Error()
			return err
		}
		if strings.Contains(strings.ToLower(res.Output), "failure") {
			res.Success = false
			res.Error = res.Output
			return fmt.Errorf("adb install failure: %s", res.Output)
		}
		res.Success = true
		res.Error = ""
		return nil
	}

	if err := tryInstall(); err != nil {
		low := strings.ToLower(res.Output + res.Error)
		switch {
		case strings.Contains(low, "signatures") || strings.Contains(low, "update_incompatible") ||
			(strings.Contains(low, "incompatible") && strings.Contains(low, "signature")):
			res.Warnings = append(res.Warnings, "signature conflict — uninstall existing package or use matching signing key")
			if reinstall && meta.Package != "" {
				_ = Uninstall(ctx, client, serial, meta.Package)
				res.Warnings = append(res.Warnings, "uninstalled "+meta.Package+" due to signing mismatch; retrying install")
				if err2 := tryInstall(); err2 == nil {
					return res, nil
				}
			}
		case strings.Contains(low, "failed to install"):
			res.Warnings = append(res.Warnings, "package manager rejected install")
		case strings.Contains(low, "no space"):
			res.Warnings = append(res.Warnings, "insufficient storage on device")
		case strings.Contains(low, "incompatible"):
			res.Warnings = append(res.Warnings, "incompatible SDK/ABI")
		}
		return res, fmt.Errorf("adb install failed: %w\n%s", err, res.Output)
	}
	return res, nil
}

// Uninstall removes the package.
func Uninstall(ctx context.Context, client *adb.Client, serial, pkg string) error {
	if pkg == "" {
		return nil
	}
	_, err := client.SerialRun(ctx, serial, "uninstall", pkg)
	return err
}

// ClearData runs pm clear.
func ClearData(ctx context.Context, client *adb.Client, serial, pkg string) error {
	if pkg == "" {
		return nil
	}
	_, err := client.Shell(ctx, serial, "pm", "clear", pkg)
	return err
}
