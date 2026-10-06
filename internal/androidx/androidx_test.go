package androidx_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/androidx"
)

func TestFramework(t *testing.T) {
	if !androidx.IsFrameworkPackage("androidx.appcompat.app.AppCompatActivity") {
		t.Fatal("expected framework")
	}
	if androidx.IsFrameworkPackage("com.example.Auth") {
		t.Fatal("app package mistagged")
	}
}

func TestKotlinSynthetic(t *testing.T) {
	if !androidx.IsKotlinSynthetic("com.example.MainActivity$coroutine$1", "invokeSuspend") {
		t.Fatal("expected kotlin synthetic")
	}
	if androidx.IsKotlinSynthetic("com.example.Auth", "authenticate") {
		t.Fatal("false positive")
	}
}

func TestNormalize(t *testing.T) {
	got := androidx.NormalizeClassName("Lcom/example/Foo;")
	if got != "com.example.Foo" {
		t.Fatalf("got %q", got)
	}
}
