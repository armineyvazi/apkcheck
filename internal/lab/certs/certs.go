// Package certs manages lab signing keystores and optional MITM CA status.
// Private key material is never returned to API clients — only paths and fingerprints.
package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Status describes certificate/keystore readiness (no secrets).
type Status struct {
	DebugKeystorePath string `json:"debug_keystore_path,omitempty"`
	DebugKeystoreOK   bool   `json:"debug_keystore_ok"`
	MITMCAPath        string `json:"mitm_ca_path,omitempty"`
	MITMCAInstalled   bool   `json:"mitm_ca_present"`
	MITMCAFingerprint string `json:"mitm_ca_fingerprint,omitempty"`
	Note              string `json:"note,omitempty"`
}

// Manager reads cert artifacts under a lab workspace.
type Manager struct {
	Root string // lab workspace root
}

// Status reports keystore + mitm CA presence without exposing private keys.
func (m *Manager) Status() Status {
	st := Status{
		Note: "Private keys are never logged or sent to the UI. Android 7+ HTTPS interception typically needs a user CA on a test image; system CA install may be blocked.",
	}
	ks := filepath.Join(m.Root, "certs", "apkcheck-debug.keystore")
	st.DebugKeystorePath = ks
	if fi, err := os.Stat(ks); err == nil && fi.Size() > 0 {
		st.DebugKeystoreOK = true
	}
	// mitmproxy confdir may live under proxy/
	for _, cand := range []string{
		filepath.Join(m.Root, "proxy", "mitmproxy-ca-cert.pem"),
		filepath.Join(m.Root, "certs", "mitmproxy-ca-cert.pem"),
	} {
		if fi, err := os.Stat(cand); err == nil && fi.Size() > 0 {
			st.MITMCAPath = cand
			st.MITMCAInstalled = true
			if fp, err := pemFingerprint(cand); err == nil {
				st.MITMCAFingerprint = fp
			}
			break
		}
	}
	return st
}

func pemFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// InstallUserCA pushes a PEM CA to the device as a user certificate (best-effort).
// On modern Android this usually requires interactive confirmation or a rooted/test image.
func InstallUserCA(adbPath, serial, pemPath string) (string, error) {
	if _, err := os.Stat(pemPath); err != nil {
		return "", err
	}
	if adbPath == "" {
		var err error
		adbPath, err = exec.LookPath("adb")
		if err != nil {
			return "", fmt.Errorf("adb not found")
		}
	}
	remote := "/sdcard/Download/apkcheck-lab-ca.crt"
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	push := append(append([]string{}, args...), "push", pemPath, remote)
	out, err := exec.Command(adbPath, push...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("adb push CA: %w\n%s", err, out)
	}
	// Open settings intent — user must confirm on device for user CA install.
	intent := append(append([]string{}, args...), "shell", "am", "start",
		"-a", "android.settings.SECURITY_SETTINGS")
	out2, _ := exec.Command(adbPath, intent...).CombinedOutput()
	msg := "CA pushed to " + remote + ". Open Settings → Security → Encryption & credentials → Install a certificate → CA certificate. " +
		"System trust store install requires root/test image on Android 7+."
	return msg + "\n" + string(out) + string(out2), nil
}
