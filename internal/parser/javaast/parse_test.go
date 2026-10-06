package javaast_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/parser/javaast"
)

const javaSrc = `package com.example;

public class Auth {
    public boolean authenticate(String password) {
        if (password == null) {
            return false;
        }
        boolean ok = password.equals("secret");
        if (!ok) {
            return false;
        }
        return true;
    }

    public void load(android.webkit.WebView view, String url) {
        view.loadUrl(url);
    }
}
`

func TestParseJavaMethods(t *testing.T) {
	ms, err := javaast.Parse(javaSrc, "Auth.java", ir.SourceJADX)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) < 2 {
		t.Fatalf("methods=%d", len(ms))
	}
	var auth *ir.MethodIR
	for _, m := range ms {
		if m.MethodName == "authenticate" {
			auth = m
		}
	}
	if auth == nil {
		t.Fatal("authenticate not found")
	}
	if auth.ClassName != "com.example.Auth" {
		t.Errorf("class=%q", auth.ClassName)
	}
	if len(auth.Calls) == 0 {
		t.Fatal("expected equals call")
	}
	found := false
	for _, c := range auth.Calls {
		if c.Name == "equals" {
			found = true
		}
	}
	if !found {
		t.Errorf("calls=%v", auth.Calls)
	}
	if auth.ControlFlow.BranchCount < 1 {
		t.Errorf("expected branches")
	}
}
