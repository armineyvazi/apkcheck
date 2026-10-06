package correlation_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/runtime/correlation"
	"github.com/armin/apkcheck/internal/runtime/logcat"
	"github.com/armin/apkcheck/pkg/model"
)

func TestLinkCrashFramesCorrelated(t *testing.T) {
	frames := []logcat.Frame{{Class: "com.example.Foo", Method: "bar", Raw: "at com.example.Foo.bar(Foo.kt:1)"}}
	methods := []model.MethodResult{{
		Ref: model.MethodRef{Class: "com.example.Foo", Name: "bar", Descriptor: "()V"},
	}}
	links := correlation.LinkCrashFrames(frames, methods)
	if len(links) != 1 || links[0].Status != "CORRELATED" {
		t.Fatalf("%+v", links)
	}
}

func TestLinkCrashFramesUnresolved(t *testing.T) {
	frames := []logcat.Frame{{Class: "com.example.Missing", Method: "x", Raw: "at com.example.Missing.x(X.java:1)"}}
	links := correlation.LinkCrashFrames(frames, nil)
	if len(links) != 1 || links[0].Status != "UNRESOLVED" {
		t.Fatalf("%+v", links)
	}
}
