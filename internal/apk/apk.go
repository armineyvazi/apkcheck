// Package apk inspects APK structure and metadata without executing code.
package apk

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/armin/apkcheck/pkg/model"
)

const (
	// MaxAPKSize is the default maximum accepted APK size (512 MiB).
	MaxAPKSize = 512 << 20
	// MaxEntries limits zip entries to mitigate zip bombs.
	MaxEntries = 200_000
	// MaxUncompressed limits total uncompressed size across entries.
	MaxUncompressed = 2 << 30 // 2 GiB
)

// Inspect reads APK zip metadata and basic structure. It does not execute code.
func Inspect(apkPath string) (*model.APKInfo, error) {
	st, err := os.Stat(apkPath)
	if err != nil {
		return nil, fmt.Errorf("stat apk: %w", err)
	}
	if st.Size() > MaxAPKSize {
		return nil, fmt.Errorf("apk exceeds size limit (%d > %d bytes)", st.Size(), MaxAPKSize)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("path is a directory, expected apk file: %s", apkPath)
	}

	sum, err := hashFile(apkPath)
	if err != nil {
		return nil, err
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk zip: %w", err)
	}
	defer zr.Close()

	if len(zr.File) > MaxEntries {
		return nil, fmt.Errorf("apk has too many entries (%d > %d)", len(zr.File), MaxEntries)
	}

	info := &model.APKInfo{
		Path:   apkPath,
		SHA256: sum,
		Size:   st.Size(),
	}

	var totalUncomp uint64
	abiSet := map[string]struct{}{}
	dexSet := []string{}

	for _, f := range zr.File {
		totalUncomp += f.UncompressedSize64
		if totalUncomp > MaxUncompressed {
			return nil, fmt.Errorf("apk uncompressed size exceeds limit")
		}
		name := path.Clean(f.Name)
		if strings.Contains(name, "..") {
			return nil, fmt.Errorf("unsafe path in apk: %s", f.Name)
		}
		switch {
		case name == "AndroidManifest.xml":
			// binary XML; package details filled later from apktool if available
		case name == "resources.arsc":
			info.HasResources = true
		case strings.HasPrefix(name, "assets/"):
			info.HasAssets = true
		case isDEX(name):
			dexSet = append(dexSet, name)
		case strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so"):
			abi, lib := splitNative(name)
			info.NativeLibs = append(info.NativeLibs, model.NativeLib{
				Path: name,
				ABI:  abi,
				Name: lib,
				Size: int64(f.UncompressedSize64),
			})
			if abi != "" {
				abiSet[abi] = struct{}{}
			}
		case strings.HasPrefix(name, "META-INF/") && (strings.HasSuffix(name, ".RSA") ||
			strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC")):
			if info.Signing == nil {
				info.Signing = &model.SigningInfo{V1Signed: true, Note: "JAR signing artifacts present"}
			} else {
				info.Signing.V1Signed = true
			}
		case name == "META-INF/MANIFEST.MF":
			if info.Signing == nil {
				info.Signing = &model.SigningInfo{Note: "META-INF present; full cert parsing deferred"}
			}
		}
	}

	sort.Strings(dexSet)
	info.DEXFiles = dexSet
	info.DEXCount = len(dexSet)
	for abi := range abiSet {
		info.ABIs = append(info.ABIs, abi)
	}
	sort.Strings(info.ABIs)
	sort.Slice(info.NativeLibs, func(i, j int) bool {
		return info.NativeLibs[i].Path < info.NativeLibs[j].Path
	})

	if info.DEXCount == 0 {
		return nil, fmt.Errorf("no classes*.dex found; not a valid dalvik APK")
	}
	return info, nil
}

// ExtractSafe extracts selected APK entries into dest with path traversal protection.
func ExtractSafe(apkPath, dest string, pred func(name string) bool) error {
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return fmt.Errorf("mkdir extract dest: %w", err)
	}
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("open apk: %w", err)
	}
	defer zr.Close()

	var written uint64
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if name == "." || strings.HasPrefix(name, "..") || strings.Contains(name, "..") {
			return fmt.Errorf("refusing unsafe apk path: %s", f.Name)
		}
		if pred != nil && !pred(name) {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) &&
			target != filepath.Clean(dest) {
			return fmt.Errorf("path traversal blocked: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		n, err := extractFile(f, target)
		if err != nil {
			return err
		}
		written += n
		if written > MaxUncompressed {
			return fmt.Errorf("extraction size limit exceeded")
		}
	}
	return nil
}

func extractFile(f *zip.File, target string) (uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(rc, int64(MaxUncompressed)))
	if err != nil {
		return uint64(n), err
	}
	return uint64(n), nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open for hash: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash apk: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isDEX(name string) bool {
	base := path.Base(name)
	if base == "classes.dex" {
		return true
	}
	if strings.HasPrefix(base, "classes") && strings.HasSuffix(base, ".dex") {
		return true
	}
	return false
}

func splitNative(name string) (abi, lib string) {
	// lib/<abi>/<name>.so
	parts := strings.Split(name, "/")
	if len(parts) >= 3 && parts[0] == "lib" {
		return parts[1], parts[len(parts)-1]
	}
	return "", path.Base(name)
}

// EnrichFromManifestYAML fills package metadata from apktool's decoded AndroidManifest.yml/xml text.
func EnrichFromManifestYAML(info *model.APKInfo, manifestXML string) {
	if info == nil {
		return
	}
	info.Package = attr(manifestXML, "package")
	if v := attr(manifestXML, "android:versionName"); v != "" {
		info.VersionName = v
	}
	if v := attr(manifestXML, "android:versionCode"); v != "" {
		var code int64
		fmt.Sscanf(v, "%d", &code)
		info.VersionCode = code
	}
	info.Permissions = unique(collectTags(manifestXML, "uses-permission", "android:name"))
	info.Activities = unique(collectTags(manifestXML, "activity", "android:name"))
	info.Services = unique(collectTags(manifestXML, "service", "android:name"))
	info.Receivers = unique(collectTags(manifestXML, "receiver", "android:name"))
	info.Providers = unique(collectTags(manifestXML, "provider", "android:name"))

	info.ExportedActivities = unique(collectExported(manifestXML, "activity"))
	info.ExportedServices = unique(collectExported(manifestXML, "service"))
	info.ExportedReceivers = unique(collectExported(manifestXML, "receiver"))
	info.ExportedProviders = unique(collectExported(manifestXML, "provider"))

	if v := boolAttrInApplication(manifestXML, "android:debuggable"); v != nil {
		info.Debuggable = v
	}
	if v := boolAttrInApplication(manifestXML, "android:allowBackup"); v != nil {
		info.AllowBackup = v
	}
	if v := boolAttrInApplication(manifestXML, "android:usesCleartextTraffic"); v != nil {
		info.UsesCleartext = v
	}
	if v := attrInApplication(manifestXML, "android:networkSecurityConfig"); v != "" {
		info.NetworkSecurityCfg = v
	}

	if v := sdkAttr(manifestXML, "minSdkVersion"); v != 0 {
		info.MinSDK = v
	}
	if v := sdkAttr(manifestXML, "targetSdkVersion"); v != 0 {
		info.TargetSDK = v
	}
}

// collectExported returns component names that are exported=true, or have an
// intent-filter without explicit exported=false (legacy implicit export).
func collectExported(xml, tag string) []string {
	var out []string
	search := "<" + tag
	rest := xml
	for {
		i := strings.Index(rest, search)
		if i < 0 {
			break
		}
		rest = rest[i:]
		// Find end of component: next sibling close or self-close region (approx)
		end := findComponentEnd(rest, tag)
		if end < 0 {
			break
		}
		chunk := rest[:end]
		name := attr(chunk, "android:name")
		if name == "" {
			rest = rest[end:]
			continue
		}
		exp := attr(chunk, "android:exported")
		hasFilter := strings.Contains(chunk, "<intent-filter")
		switch strings.ToLower(exp) {
		case "true":
			out = append(out, name)
		case "false":
			// not exported
		default:
			if hasFilter {
				out = append(out, name)
			}
		}
		rest = rest[end:]
	}
	return out
}

func findComponentEnd(rest, tag string) int {
	// Prefer matching close tag; fall back to next component start / application close.
	closeTag := "</" + tag
	if j := strings.Index(rest, closeTag); j >= 0 {
		gt := strings.Index(rest[j:], ">")
		if gt >= 0 {
			return j + gt + 1
		}
	}
	// self-closing first line
	if gt := strings.Index(rest, "/>"); gt >= 0 && gt < 500 {
		return gt + 2
	}
	// next tag of same kind or end
	next := strings.Index(rest[1:], "<"+tag)
	if next >= 0 {
		return next + 1
	}
	if j := strings.Index(rest, "</application"); j >= 0 {
		return j
	}
	if len(rest) > 4000 {
		return 4000
	}
	return len(rest)
}

func boolAttrInApplication(xml, key string) *bool {
	v := attrInApplication(xml, key)
	if v == "" {
		return nil
	}
	b := strings.EqualFold(v, "true")
	return &b
}

func attrInApplication(xml, key string) string {
	i := strings.Index(xml, "<application")
	if i < 0 {
		return ""
	}
	rest := xml[i:]
	end := strings.Index(rest, ">")
	if end < 0 {
		return ""
	}
	return attr(rest[:end+1], key)
}

func attr(xml, key string) string {
	key += `="`
	i := strings.Index(xml, key)
	if i < 0 {
		return ""
	}
	rest := xml[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func collectTags(xml, tag, attrName string) []string {
	var out []string
	search := "<" + tag
	rest := xml
	for {
		i := strings.Index(rest, search)
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := strings.Index(rest, ">")
		if end < 0 {
			break
		}
		chunk := rest[:end+1]
		if v := attr(chunk, attrName); v != "" {
			out = append(out, v)
		}
		rest = rest[end+1:]
	}
	return out
}

func sdkAttr(xml, name string) int {
	// <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
	v := attr(xml, "android:"+name)
	if v == "" {
		return 0
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	return n
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
