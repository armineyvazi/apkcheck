package env

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// EnsurePlatformTools makes sure <sdkRoot>/platform-tools exists.
// Android Emulator refuses to start without it ("Broken AVD system path"),
// even when adb is available elsewhere on PATH.
//
// On Windows the Android Studio installer places platform-tools correctly, so
// this function is a no-op there. On macOS/Linux a symlink is created when
// platform-tools was installed separately (e.g. Homebrew cask).
//
// Returns a short note when a symlink was created.
func EnsurePlatformTools(sdkRoot string) (string, error) {
	if sdkRoot == "" {
		return "", fmt.Errorf("empty sdk root")
	}
	if runtime.GOOS == "windows" {
		return "", nil
	}

	dest := filepath.Join(sdkRoot, "platform-tools")
	if st, err := os.Stat(dest); err == nil && st.IsDir() {
		if _, err := os.Stat(filepath.Join(dest, exeName("adb"))); err == nil {
			return "", nil
		}
	}

	src, err := findPlatformToolsDir()
	if err != nil {
		hint := "brew install --cask android-platform-tools"
		if runtime.GOOS == "linux" {
			hint = "sudo apt install android-sdk-platform-tools  # or download from developer.android.com/tools"
		}
		return "", fmt.Errorf("platform-tools missing under %s and could not locate system platform-tools: %w\nFix: %s", sdkRoot, err, hint)
	}

	_ = os.RemoveAll(dest)
	if err := os.Symlink(src, dest); err != nil {
		return "", fmt.Errorf("symlink %s -> %s: %w (run as user that can write ANDROID_HOME)", src, dest, err)
	}
	return fmt.Sprintf("linked platform-tools -> %s", src), nil
}

func findPlatformToolsDir() (string, error) {
	var candidates []string

	if p, err := exec.LookPath(exeName("adb")); err == nil {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			candidates = append(candidates, filepath.Dir(real))
		}
		candidates = append(candidates, filepath.Dir(p))
	}

	if runtime.GOOS == "darwin" {
		for _, base := range []string{
			"/opt/homebrew/Caskroom/android-platform-tools",
			"/usr/local/Caskroom/android-platform-tools",
		} {
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					candidates = append(candidates, filepath.Join(base, e.Name(), "platform-tools"))
				}
			}
		}
	}

	seen := map[string]bool{}
	for _, c := range candidates {
		c = filepath.Clean(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if !strings.HasSuffix(c, "platform-tools") {
			continue
		}
		if st, err := os.Stat(filepath.Join(c, exeName("adb"))); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("no platform-tools directory with adb found")
}
