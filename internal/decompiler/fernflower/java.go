package fernflower

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/armin/apkcheck/internal/runner"
)

// JavaRequirement describes the JVM needed to run a FernFlower jar.
type JavaRequirement struct {
	MinMajor   int // class-file major (e.g. 69 → Java 25)
	MinRelease int // human Java release (25)
	JarPath    string
	JavaPath   string // selected java binary
	JavaVer    string
}

var javaVersionRE = regexp.MustCompile(`version "([0-9]+)(?:\.([0-9]+))?`)

// ResolveJava picks a JVM that can execute the FernFlower jar.
// Homebrew fernflower (2025+) ships bytecode targeting Java 25+.
func (d *Decompiler) ResolveJava(ctx context.Context) (*JavaRequirement, error) {
	exe, jar, err := d.resolve()
	if err != nil {
		return nil, err
	}
	req := &JavaRequirement{JarPath: jar, MinRelease: 8, MinMajor: 52}
	if jar != "" {
		if major, ok := jarClassMajor(jar); ok {
			req.MinMajor = major
			req.MinRelease = major - 44 // Java 1.1=45 … Java 25=69
			if req.MinRelease < 8 {
				req.MinRelease = 8
			}
		}
	}

	candidates := []string{}
	if d.JavaPath != "" {
		candidates = append(candidates, d.JavaPath)
	}
	if jar != "" {
		// Prefer modern Homebrew JDKs when the jar needs them.
		for _, home := range []string{
			"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java",
			"/opt/homebrew/opt/openjdk@27/libexec/openjdk.jdk/Contents/Home/bin/java",
			"/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home/bin/java",
			"/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home/bin/java",
			"/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java",
		} {
			candidates = append(candidates, home)
		}
	}
	if exe != "" && strings.Contains(filepath.Base(exe), "java") {
		candidates = append(candidates, exe)
	}
	if p, err := runner.LookPath("", "java"); err == nil {
		candidates = append(candidates, p)
	}

	var lastErr error
	seen := map[string]bool{}
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			continue
		}
		ver, release, err := probeJavaRelease(ctx, c)
		if err != nil {
			lastErr = err
			continue
		}
		if release < req.MinRelease {
			lastErr = fmt.Errorf("%s is Java %d; FernFlower needs Java %d+", c, release, req.MinRelease)
			continue
		}
		req.JavaPath = c
		req.JavaVer = ver
		return req, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("FernFlower requires Java %d+ (jar class major %d): %w\nHint: brew install openjdk && export PATH=\"/opt/homebrew/opt/openjdk/bin:$PATH\"",
			req.MinRelease, req.MinMajor, lastErr)
	}
	return nil, fmt.Errorf("FernFlower requires Java %d+; no compatible java found (brew install openjdk)", req.MinRelease)
}

func jarClassMajor(jarPath string) (int, bool) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return 0, false
	}
	defer zr.Close()
	// Prefer main class; otherwise first .class under org/jetbrains/java/decompiler.
	var fallback int
	for _, f := range zr.File {
		name := f.Name
		if !strings.HasSuffix(name, ".class") || strings.Contains(name, "module-info") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		hdr := make([]byte, 8)
		_, err = rc.Read(hdr)
		rc.Close()
		if err != nil || binary.BigEndian.Uint32(hdr[0:4]) != 0xCAFEBABE {
			continue
		}
		major := int(binary.BigEndian.Uint16(hdr[6:8]))
		if strings.Contains(name, "ConsoleDecompiler.class") {
			return major, true
		}
		if fallback == 0 && strings.Contains(name, "org/jetbrains/java/decompiler/") {
			fallback = major
		}
	}
	if fallback > 0 {
		return fallback, true
	}
	return 0, false
}

func probeJavaRelease(ctx context.Context, javaPath string) (string, int, error) {
	cmd := exec.CommandContext(ctx, javaPath, "-version")
	out, err := cmd.CombinedOutput()
	s := string(out)
	m := javaVersionRE.FindStringSubmatch(s)
	if m == nil {
		if err != nil {
			return "", 0, err
		}
		return strings.TrimSpace(firstLine(s)), 0, fmt.Errorf("cannot parse java -version from %s", javaPath)
	}
	major, _ := strconv.Atoi(m[1])
	// Legacy 1.8.x
	if major == 1 && len(m) > 2 && m[2] != "" {
		major, _ = strconv.Atoi(m[2])
	}
	return firstLine(s), major, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
