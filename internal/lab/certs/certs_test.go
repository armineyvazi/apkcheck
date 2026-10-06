package certs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/lab/certs"
)

func TestStatusEmpty(t *testing.T) {
	root := t.TempDir()
	m := &certs.Manager{Root: root}
	st := m.Status()
	if st.DebugKeystoreOK {
		t.Fatal("expected no keystore")
	}
	_ = os.MkdirAll(filepath.Join(root, "certs"), 0o750)
	_ = os.WriteFile(filepath.Join(root, "certs", "apkcheck-debug.keystore"), []byte("x"), 0o640)
	st = m.Status()
	if !st.DebugKeystoreOK {
		t.Fatal("expected keystore ok")
	}
}
