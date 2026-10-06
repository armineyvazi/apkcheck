// Package env locates the Android SDK and related tools without hard-coded paths.
package env

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SDK describes a discovered Android SDK installation.
type SDK struct {
	Root     string
	ADB      string
	Emulator string
	AAPT     string
	AAPT2    string
	HostArch string // arm64 | amd64 | ...
	JavaHome string // JDK 17+ home used for sdkmanager/avdmanager
}

// Discover finds the Android SDK by checking environment variables and
// platform-specific default installation locations.
func Discover() SDK {
	var s SDK
	s.HostArch = runtime.GOARCH
	var roots []string
	if v := os.Getenv("ANDROID_SDK_ROOT"); v != "" {
		roots = append(roots, v)
	}
	if v := os.Getenv("ANDROID_HOME"); v != "" {
		roots = append(roots, v)
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		if lad := os.Getenv("LOCALAPPDATA"); lad != "" {
			roots = append(roots, filepath.Join(lad, "Android", "Sdk"))
		}
		if home != "" {
			roots = append(roots, filepath.Join(home, "AppData", "Local", "Android", "Sdk"))
		}
	case "darwin":
		if home != "" {
			roots = append(roots,
				filepath.Join(home, "Library", "Android", "sdk"),
				filepath.Join(home, "Android", "Sdk"),
				"/opt/homebrew/share/android-commandlinetools",
				"/usr/local/share/android-commandlinetools",
				"/usr/local/share/android-sdk",
				"/opt/android-sdk",
			)
		} else {
			roots = append(roots, "/opt/homebrew/share/android-commandlinetools")
		}
	default: // linux and others
		if home != "" {
			roots = append(roots, filepath.Join(home, "Android", "Sdk"))
		}
		roots = append(roots,
			"/opt/android-sdk",
			"/usr/lib/android-sdk",
			"/usr/local/share/android-sdk",
		)
	}

	for _, root := range roots {
		if st, err := os.Stat(root); err == nil && st.IsDir() {
			s.Root = root
			break
		}
	}

	// Prefer PATH for adb; exec.LookPath handles .exe on Windows.
	if p := look("adb"); p != "" {
		s.ADB = p
	} else if s.Root != "" {
		cand := filepath.Join(s.Root, "platform-tools", exeName("adb"))
		if fileExists(cand) {
			s.ADB = cand
		}
	}

	if p := look("emulator"); p != "" {
		s.Emulator = p
	} else if s.Root != "" {
		cand := filepath.Join(s.Root, "emulator", exeName("emulator"))
		if fileExists(cand) {
			s.Emulator = cand
		}
	}

	for _, name := range []string{"aapt2", "aapt"} {
		if p := look(name); p != "" {
			if name == "aapt2" {
				s.AAPT2 = p
			} else {
				s.AAPT = p
			}
			continue
		}
		if s.Root == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(s.Root, "build-tools", "*", exeName(name)))
		if len(matches) > 0 {
			if name == "aapt2" {
				s.AAPT2 = matches[len(matches)-1]
			} else {
				s.AAPT = matches[len(matches)-1]
			}
		}
	}
	return s
}

// CompatibleWithAVD reports whether host arch can run the AVD ABI.
func (s SDK) CompatibleWithAVD(avdABI string) (bool, string) {
	abi := strings.ToLower(avdABI)
	host := s.HostArch
	if abi == "" {
		return true, ""
	}
	switch host {
	case "arm64":
		if strings.Contains(abi, "arm64") || strings.Contains(abi, "aarch64") {
			return true, ""
		}
		if strings.Contains(abi, "x86") {
			return false, "Selected AVD is incompatible with the host architecture.\n\nHost:\n    arm64\n\nAVD:\n    " + avdABI + "\n\nSuggestion:\n    Use an arm64-v8a Android system image.\n"
		}
	case "amd64", "386":
		if strings.Contains(abi, "x86") {
			return true, ""
		}
		if strings.Contains(abi, "arm") {
			return false, "Selected AVD is incompatible with the host architecture.\n\nHost:\n    " + host + "\n\nAVD:\n    " + avdABI + "\n\nSuggestion:\n    Use an x86_64 Android system image.\n"
		}
	}
	return true, ""
}

// look finds name on PATH; exec.LookPath adds .exe automatically on Windows.
func look(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// exeName appends .exe on Windows.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
