package env_test

import (
	"os"
	"testing"

	"github.com/armin/apkcheck/internal/runtime/env"
)

func TestBootstrapSetsEnv(t *testing.T) {
	sdk, err := env.Bootstrap()
	if err != nil {
		t.Skip(err)
	}
	if sdk.Root == "" {
		t.Fatal("empty root")
	}
	if os.Getenv("ANDROID_HOME") == "" {
		t.Fatal("ANDROID_HOME not set")
	}
	if os.Getenv("ANDROID_SDK_ROOT") == "" {
		t.Fatal("ANDROID_SDK_ROOT not set")
	}
}

func TestFindJavaHome17(t *testing.T) {
	home := env.FindJavaHome(17)
	if home == "" {
		t.Skip("no JDK 17+ installed")
	}
	if _, err := os.Stat(home + "/bin/java"); err != nil {
		t.Fatal(err)
	}
}
