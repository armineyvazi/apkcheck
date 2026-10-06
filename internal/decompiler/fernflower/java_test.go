package fernflower

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveJavaPicksModernJDK(t *testing.T) {
	matches, _ := filepath.Glob("/opt/homebrew/opt/fernflower/libexec/*.jar")
	if len(matches) == 0 {
		t.Skip("fernflower jar not installed")
	}
	d := New(matches[0], "") // force jar path; ignore PATH java 17
	req, err := d.ResolveJava(context.Background())
	if err != nil {
		t.Fatalf("ResolveJava: %v", err)
	}
	if req.MinRelease < 21 {
		t.Fatalf("expected modern fernflower min release >= 21, got %d", req.MinRelease)
	}
	if req.JavaPath == "" {
		t.Fatal("no java selected")
	}
	if _, err := os.Stat(req.JavaPath); err != nil {
		t.Fatalf("java path: %v", err)
	}
	t.Logf("jar needs Java %d+; selected %s (%s)", req.MinRelease, req.JavaPath, req.JavaVer)
}

func TestJarClassMajor(t *testing.T) {
	matches, _ := filepath.Glob("/opt/homebrew/opt/fernflower/libexec/*.jar")
	if len(matches) == 0 {
		t.Skip("fernflower jar not installed")
	}
	major, ok := jarClassMajor(matches[0])
	if !ok || major < 52 {
		t.Fatalf("jarClassMajor=%d ok=%v", major, ok)
	}
}
