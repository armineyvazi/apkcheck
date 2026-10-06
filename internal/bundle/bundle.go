// Package bundle resolves modern Android package formats into a logical APK set.
// Supported: APK, split APK directories, XAPK, APKS, APKM, AAB (best-effort).
package bundle

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/pkg/model"
)

// Resolved is a logical application ready for analysis.
type Resolved struct {
	Info    *model.APKInfo
	Bundle  *model.BundleInfo
	WorkAPK string   // primary APK path to feed apktool (base)
	AllAPKs []string // all split APKs
	WorkDir string   // extraction directory (caller owns cleanup if KeepTemp)
}

// Resolve accepts an APK, split directory, XAPK/APKS/APKM, or AAB and returns
// a logical application. Analysis should treat WorkAPK as the Smali entry point
// and AllAPKs for native/resource inventory.
func Resolve(input, dest string) (*Resolved, error) {
	st, err := os.Stat(input)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return resolveDir(input, dest)
	}
	lower := strings.ToLower(input)
	switch {
	case strings.HasSuffix(lower, ".apk"):
		return resolveSingle(input)
	case strings.HasSuffix(lower, ".xapk"),
		strings.HasSuffix(lower, ".apks"),
		strings.HasSuffix(lower, ".apkm"):
		return resolveZipBundle(input, dest, extKind(lower))
	case strings.HasSuffix(lower, ".aab"):
		return resolveAAB(input, dest)
	default:
		// Try as zip of APKs
		return resolveZipBundle(input, dest, "unknown")
	}
}

func extKind(lower string) string {
	switch {
	case strings.HasSuffix(lower, ".xapk"):
		return "xapk"
	case strings.HasSuffix(lower, ".apks"):
		return "apks"
	case strings.HasSuffix(lower, ".apkm"):
		return "apkm"
	default:
		return "unknown"
	}
}

func resolveSingle(apkPath string) (*Resolved, error) {
	info, err := apk.Inspect(apkPath)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(apkPath)
	bi := &model.BundleInfo{
		Format:      "apk",
		LogicalPath: apkPath,
		BaseAPK:     apkPath,
		Splits: []model.SplitOrigin{{
			Name:     "base",
			Path:     apkPath,
			Kind:     "base",
			SHA256:   info.SHA256,
			DEXFiles: info.DEXFiles,
			Libs:     libPaths(info.NativeLibs),
		}},
	}
	info.SplitOrigins = map[string]string{}
	for _, d := range info.DEXFiles {
		info.SplitOrigins[d] = "base"
	}
	for _, n := range info.NativeLibs {
		info.SplitOrigins[n.Path] = "base"
	}
	_ = name
	return &Resolved{Info: info, Bundle: bi, WorkAPK: apkPath, AllAPKs: []string{apkPath}}, nil
}

func resolveDir(dir, dest string) (*Resolved, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var apks []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".apk") {
			apks = append(apks, filepath.Join(dir, e.Name()))
		}
	}
	if len(apks) == 0 {
		return nil, fmt.Errorf("no .apk files in directory: %s", dir)
	}
	sort.Strings(apks)
	return mergeAPKs(apks, dest, "split_apk", dir)
}

func resolveZipBundle(path, dest, format string) (*Resolved, error) {
	if dest == "" {
		dest = filepath.Join(os.TempDir(), "apkcheck-bundle")
	}
	extractDir := filepath.Join(dest, "splits_"+hashShort(path))
	_ = os.RemoveAll(extractDir)
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		return nil, err
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer zr.Close()

	var apks []string
	var manifestJSON []byte
	for _, f := range zr.File {
		name := pathClean(f.Name)
		base := filepath.Base(name)
		lower := strings.ToLower(base)
		if lower == "manifest.json" || lower == "info.json" {
			rc, err := f.Open()
			if err == nil {
				manifestJSON, _ = io.ReadAll(io.LimitReader(rc, 1<<20))
				rc.Close()
			}
			continue
		}
		if !strings.HasSuffix(lower, ".apk") {
			continue
		}
		target := filepath.Join(extractDir, base)
		if err := extractZipFile(f, target); err != nil {
			return nil, err
		}
		apks = append(apks, target)
	}
	if len(apks) == 0 {
		return nil, fmt.Errorf("%s contains no APK splits", format)
	}
	sort.Strings(apks)
	res, err := mergeAPKs(apks, dest, format, path)
	if err != nil {
		return nil, err
	}
	if len(manifestJSON) > 0 {
		res.Bundle.Notes = append(res.Bundle.Notes, "bundle manifest.json present")
		var meta map[string]any
		if json.Unmarshal(manifestJSON, &meta) == nil {
			if pkg, ok := meta["package_name"].(string); ok && pkg != "" && res.Info.Package == "" {
				res.Info.Package = pkg
			}
			if pkg, ok := meta["packageName"].(string); ok && pkg != "" && res.Info.Package == "" {
				res.Info.Package = pkg
			}
		}
	}
	res.WorkDir = extractDir
	return res, nil
}

func resolveAAB(input, dest string) (*Resolved, error) {
	if dest == "" {
		dest = filepath.Join(os.TempDir(), "apkcheck-aab")
	}
	extractDir := filepath.Join(dest, "aab_"+hashShort(input))
	_ = os.RemoveAll(extractDir)
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		return nil, err
	}
	// AAB is a zip; DEX lives under base/dex/*.dex. Build a synthetic APK-like zip
	// with those DEX files so apktool/JADX pipelines can consume it.
	zr, err := zip.OpenReader(input)
	if err != nil {
		return nil, fmt.Errorf("open aab: %w", err)
	}
	defer zr.Close()

	synth := filepath.Join(extractDir, "base-from-aab.apk")
	out, err := os.Create(synth)
	if err != nil {
		return nil, err
	}
	zw := zip.NewWriter(out)

	var dexCount int
	var libs []model.NativeLib
	abiSet := map[string]struct{}{}
	origins := map[string]string{}

	for _, f := range zr.File {
		name := pathClean(f.Name)
		switch {
		case strings.HasPrefix(name, "base/dex/") && strings.HasSuffix(name, ".dex"):
			base := path.Base(name)
			if err := copyZipEntry(zw, f, base); err != nil {
				zw.Close()
				out.Close()
				return nil, err
			}
			origins[base] = "base"
			dexCount++
		case strings.HasPrefix(name, "base/lib/") && strings.HasSuffix(name, ".so"):
			rel := strings.TrimPrefix(name, "base/")
			if err := copyZipEntry(zw, f, rel); err != nil {
				zw.Close()
				out.Close()
				return nil, err
			}
			parts := strings.Split(rel, "/")
			abi, lib := "", path.Base(rel)
			if len(parts) >= 3 {
				abi = parts[1]
			}
			libs = append(libs, model.NativeLib{Path: rel, ABI: abi, Name: lib, Size: int64(f.UncompressedSize64)})
			if abi != "" {
				abiSet[abi] = struct{}{}
			}
			origins[rel] = "base"
		case name == "base/manifest/AndroidManifest.xml":
			_ = copyZipEntry(zw, f, "AndroidManifest.xml")
		case name == "BundleConfig.pb":
			// noted only
		}
	}
	if err := zw.Close(); err != nil {
		out.Close()
		return nil, err
	}
	out.Close()
	if dexCount == 0 {
		return nil, fmt.Errorf("aab has no base/dex/*.dex — install bundletool for full conversion")
	}

	info, err := apk.Inspect(synth)
	if err != nil {
		// Inspect may fail if no binary manifest; synthesize minimal info
		sum, _ := fileSHA(synth)
		st, _ := os.Stat(synth)
		info = &model.APKInfo{
			Path: synth, SHA256: sum, Size: st.Size(),
			DEXCount: dexCount, NativeLibs: libs, SplitOrigins: origins,
		}
		for abi := range abiSet {
			info.ABIs = append(info.ABIs, abi)
		}
		sort.Strings(info.ABIs)
	} else {
		info.SplitOrigins = origins
		if len(libs) > 0 {
			info.NativeLibs = libs
		}
	}
	info.Path = input // logical path is the AAB
	bi := &model.BundleInfo{
		Format:      "aab",
		LogicalPath: input,
		BaseAPK:     synth,
		Splits: []model.SplitOrigin{{
			Name: "base", Path: synth, Kind: "base", SHA256: info.SHA256,
			DEXFiles: info.DEXFiles, Libs: libPaths(libs),
		}},
		Notes: []string{
			"AAB analyzed via base/dex extraction (not full bundletool install set).",
			"Feature modules / config splits may be incomplete without bundletool.",
		},
	}
	return &Resolved{
		Info: info, Bundle: bi, WorkAPK: synth, AllAPKs: []string{synth}, WorkDir: extractDir,
	}, nil
}

func mergeAPKs(apks []string, dest, format, logical string) (*Resolved, error) {
	if len(apks) == 0 {
		return nil, fmt.Errorf("no apks to merge")
	}
	base := pickBase(apks)
	baseInfo, err := apk.Inspect(base)
	if err != nil {
		return nil, fmt.Errorf("inspect base %s: %w", base, err)
	}

	bi := &model.BundleInfo{
		Format:      format,
		LogicalPath: logical,
		BaseAPK:     base,
	}
	origins := map[string]string{}
	abiSet := map[string]struct{}{}
	var allLibs []model.NativeLib
	var allDEX []string

	for _, p := range apks {
		info, err := apk.Inspect(p)
		if err != nil {
			// config-only splits may lack DEX
			info = &model.APKInfo{Path: p}
			if zr, e := zip.OpenReader(p); e == nil {
				for _, f := range zr.File {
					n := pathClean(f.Name)
					if strings.HasPrefix(n, "lib/") && strings.HasSuffix(n, ".so") {
						parts := strings.Split(n, "/")
						abi, lib := "", path.Base(n)
						if len(parts) >= 3 {
							abi = parts[1]
						}
						info.NativeLibs = append(info.NativeLibs, model.NativeLib{
							Path: n, ABI: abi, Name: lib, Size: int64(f.UncompressedSize64),
						})
					}
				}
				zr.Close()
			}
		}
		splitName := splitNameFromPath(p, p == base)
		kind := classifySplit(splitName, len(info.DEXFiles) > 0)
		bi.Splits = append(bi.Splits, model.SplitOrigin{
			Name: splitName, Path: p, Kind: kind, SHA256: info.SHA256,
			DEXFiles: info.DEXFiles, Libs: libPaths(info.NativeLibs),
		})
		for _, d := range info.DEXFiles {
			key := splitName + ":" + d
			allDEX = append(allDEX, key)
			origins[d] = splitName
			origins[key] = splitName
		}
		for _, n := range info.NativeLibs {
			allLibs = append(allLibs, n)
			origins[n.Path] = splitName
			if n.ABI != "" {
				abiSet[n.ABI] = struct{}{}
			}
		}
	}

	// Prefer base DEX inventory; annotate combined libs
	baseInfo.Path = logical
	baseInfo.NativeLibs = dedupeLibs(allLibs)
	baseInfo.SplitOrigins = origins
	baseInfo.ABIs = nil
	for abi := range abiSet {
		baseInfo.ABIs = append(baseInfo.ABIs, abi)
	}
	sort.Strings(baseInfo.ABIs)
	if len(apks) > 1 {
		bi.Notes = append(bi.Notes,
			fmt.Sprintf("logical app assembled from %d splits; Smali ground truth from base APK", len(apks)),
			"classes/resources/native libs tagged with split origin in SplitOrigins",
		)
	}
	_ = allDEX
	_ = dest
	return &Resolved{
		Info: baseInfo, Bundle: bi, WorkAPK: base, AllAPKs: apks,
	}, nil
}

func pickBase(apks []string) string {
	for _, p := range apks {
		base := strings.ToLower(filepath.Base(p))
		if base == "base.apk" || strings.HasPrefix(base, "base") && strings.HasSuffix(base, ".apk") {
			return p
		}
	}
	// Prefer APK with most DEX
	best, bestN := apks[0], -1
	for _, p := range apks {
		info, err := apk.Inspect(p)
		n := 0
		if err == nil {
			n = info.DEXCount
		}
		if n > bestN {
			best, bestN = p, n
		}
	}
	return best
}

func splitNameFromPath(p string, isBase bool) string {
	if isBase {
		return "base"
	}
	base := filepath.Base(p)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimPrefix(base, "split_")
	base = strings.TrimPrefix(base, "config.")
	if base == "" {
		return "unknown"
	}
	return base
}

func classifySplit(name string, hasDEX bool) string {
	n := strings.ToLower(name)
	if name == "base" || hasDEX && (n == "base" || strings.HasPrefix(n, "base")) {
		return "base"
	}
	for _, abi := range []string{"arm64", "armeabi", "x86", "x86_64", "mips"} {
		if strings.Contains(n, abi) {
			return "abi"
		}
	}
	for _, d := range []string{"ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi", "tvdpi", "anydpi"} {
		if strings.Contains(n, d) {
			return "density"
		}
	}
	if len(n) <= 6 && !strings.Contains(n, ".") {
		// likely locale like en, fa, de
		return "locale"
	}
	if strings.Contains(n, "config.") || strings.HasPrefix(n, "config") {
		return "config"
	}
	return "feature"
}

func libPaths(libs []model.NativeLib) []string {
	out := make([]string, 0, len(libs))
	for _, l := range libs {
		out = append(out, l.Path)
	}
	return out
}

func dedupeLibs(in []model.NativeLib) []model.NativeLib {
	seen := map[string]struct{}{}
	var out []model.NativeLib
	for _, l := range in {
		if _, ok := seen[l.Path]; ok {
			continue
		}
		seen[l.Path] = struct{}{}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func pathClean(name string) string {
	return path.Clean(strings.ReplaceAll(name, "\\", "/"))
}

func extractZipFile(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(rc, 512<<20))
	return err
}

func copyZipEntry(zw *zip.Writer, f *zip.File, name string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(w, io.LimitReader(rc, 512<<20))
	return err
}

func hashShort(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:6])
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
