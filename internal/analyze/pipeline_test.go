package analyze_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/diff"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/parser/javaast"
	"github.com/armin/apkcheck/internal/smali"
	"github.com/armin/apkcheck/pkg/model"
)

func TestEndToEndSemanticCompare(t *testing.T) {
	smaliSrc := `.class public Lcom/example/Auth;
.method public authenticate(Ljava/lang/String;)Z
    .locals 2
    const-string v0, "secret"
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-eqz v1, :fail
    return v1
    :fail
    const/4 v1, 0x0
    return v1
.end method
`
	javaSrc := `package com.example;
public class Auth {
  public boolean authenticate(String password) {
    if (password == null) return false;
    return password.equals("secret");
  }
}
`
	sms, err := smali.Parse(smaliSrc, "Auth.smali")
	if err != nil || len(sms) != 1 {
		t.Fatalf("smali: %v len=%d", err, len(sms))
	}
	jms, err := javaast.Parse(javaSrc, "Auth.java", ir.SourceJADX)
	if err != nil || len(jms) == 0 {
		t.Fatalf("java: %v", err)
	}
	idx := diff.IndexByFuzzyKey(jms)
	matched := diff.Match(sms[0], idx)
	if matched == nil {
		t.Fatal("no match")
	}
	res := diff.CompareMethod(sms[0], map[string]*ir.MethodIR{"jadx": matched})
	if res.Status == model.ConfidenceDisagreement {
		t.Fatalf("unexpected disagreement: %+v", res.Issues)
	}
}
