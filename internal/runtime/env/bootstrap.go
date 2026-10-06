package env

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var javaVerRE = regexp.MustCompile(`version "([0-9]+)(?:\.([0-9]+))?`)

// Bootstrap discovers the Android SDK + a usable JDK, then sets process env
// (ANDROID_HOME, ANDROID_SDK_ROOT, JAVA_HOME, PATH) so sdkmanager/avdmanager/emulator work.
// Safe to call multiple times.
func Bootstrap() (SDK, error) {
	s := Discover()
	if s.Root == "" {
		return s, fmt.Errorf("Android SDK not found\n" +
			"Set ANDROID_HOME or ANDROID_SDK_ROOT, or install Android Studio.\n" +
			"  macOS:   brew install --cask android-commandlinetools\n" +
			"  Linux:   install Android Studio or sdk-tools from developer.android.com\n" +
			"  Windows: install Android Studio (includes SDK) from developer.android.com\n" +
			"Then re-run — apkcheck sets ANDROID_HOME automatically when the SDK is present")
	}

	_ = os.Setenv("ANDROID_HOME", s.Root)
	_ = os.Setenv("ANDROID_SDK_ROOT", s.Root)

	// Emulator FATAL: "Broken AVD system path" when platform-tools/ is missing under SDK root
	// (common with Homebrew: commandlinetools + platform-tools are separate casks).
	if note, err := EnsurePlatformTools(s.Root); err != nil {
		return s, fmt.Errorf("SDK layout: %w", err)
	} else if note != "" {
		// non-fatal informational; callers that log can ignore
		_ = note
	}

	javaHome := FindJavaHome(17)
	if javaHome != "" {
		s.JavaHome = javaHome
		_ = os.Setenv("JAVA_HOME", javaHome)
	}

	pathParts := []string{}
	if javaHome != "" {
		pathParts = append(pathParts, filepath.Join(javaHome, "bin"))
	}
	for _, p := range []string{
		filepath.Join(s.Root, "cmdline-tools", "latest", "bin"),
		filepath.Join(s.Root, "emulator"),
		filepath.Join(s.Root, "platform-tools"),
		filepath.Join(s.Root, "tools", "bin"),
	} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			pathParts = append(pathParts, p)
		}
	}
	// Prefer SDK tools over stale PATH entries.
	_ = os.Setenv("PATH", strings.Join(pathParts, string(os.PathListSeparator))+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Re-resolve after PATH update.
	s2 := Discover()
	s2.JavaHome = s.JavaHome
	if s2.Root == "" {
		s2.Root = s.Root
	}
	if s2.Emulator == "" {
		s2.Emulator = s.Emulator
	}
	if s2.ADB == "" {
		s2.ADB = s.ADB
	}
	return s2, nil
}

// FindJavaHome returns a JDK home directory with release >= minRelease (e.g. 17).
func FindJavaHome(minRelease int) string {
	var candidates []string
	if v := os.Getenv("JAVA_HOME"); v != "" {
		candidates = append(candidates, v)
	}
	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates,
			"/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
			"/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
			"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
			"/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
			"/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
		)
		if out, err := exec.Command("/usr/libexec/java_home", "-v", "17+").Output(); err == nil {
			if p := strings.TrimSpace(string(out)); p != "" {
				candidates = append(candidates, p)
			}
		}
	case "windows":
		for _, base := range []string{
			`C:\Program Files\Eclipse Adoptium`,
			`C:\Program Files\Microsoft`,
			`C:\Program Files\Java`,
			`C:\Program Files\BellSoft`,
		} {
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					candidates = append(candidates, filepath.Join(base, e.Name()))
				}
			}
		}
	default: // linux
		candidates = append(candidates,
			"/usr/lib/jvm/java-17-openjdk-amd64",
			"/usr/lib/jvm/java-17-openjdk-arm64",
			"/usr/lib/jvm/java-17-openjdk",
			"/usr/lib/jvm/temurin-17",
			"/usr/lib/jvm/java-21-openjdk-amd64",
			"/usr/lib/jvm/java-21-openjdk-arm64",
			"/usr/local/lib/jvm/java-17",
		)
		// Ubuntu update-alternatives default
		if out, err := exec.Command("java", "-XshowSettings:property", "-version").CombinedOutput(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "java.home") {
					if _, val, ok := strings.Cut(line, "="); ok {
						candidates = append(candidates, strings.TrimSpace(val))
					}
					break
				}
			}
		}
	}

	var best17 string
	var bestAny string
	bestAnyRel := -1
	seen := map[string]bool{}
	for _, home := range candidates {
		if home == "" || seen[home] {
			continue
		}
		seen[home] = true
		java := filepath.Join(home, "bin", "java")
		if !fileExists(java) {
			continue
		}
		rel := probeJavaRelease(java)
		if rel < minRelease {
			continue
		}
		// Prefer a stable LTS (17) for sdkmanager/avdmanager; else highest available.
		if rel == 17 && best17 == "" {
			best17 = home
		}
		if rel > bestAnyRel {
			bestAnyRel = rel
			bestAny = home
		}
	}
	if best17 != "" {
		return best17
	}
	return bestAny
}

func probeJavaRelease(javaPath string) int {
	out, err := exec.Command(javaPath, "-version").CombinedOutput()
	if err != nil {
		return 0
	}
	m := javaVerRE.FindStringSubmatch(string(out))
	if m == nil {
		return 0
	}
	major, _ := strconv.Atoi(m[1])
	if major == 1 && len(m) > 2 && m[2] != "" {
		major, _ = strconv.Atoi(m[2])
	}
	return major
}
