package smali_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/smali"
)

const sample = `.class public Lcom/example/Auth;
.super Ljava/lang/Object;
.source "Auth.java"

.method public authenticate(Ljava/lang/String;)Z
    .locals 3

    const-string v0, "secret"
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-eqz v1, :cond_fail

    sget-object v2, Lcom/example/Auth;->ok:Z
    return v1

    :cond_fail
    const/4 v1, 0x0
    return v1
.end method

.method public declared-synchronized lock()V
    .locals 1
    monitor-enter p0
    monitor-exit p0
    return-void
.end method
`

func TestParseMethodBasics(t *testing.T) {
	ms, err := smali.Parse(sample, "Auth.smali")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("want 2 methods, got %d", len(ms))
	}
	m := ms[0]
	if m.ClassName != "com.example.Auth" {
		t.Errorf("class=%q", m.ClassName)
	}
	if m.MethodName != "authenticate" {
		t.Errorf("name=%q", m.MethodName)
	}
	if m.Descriptor != "(Ljava/lang/String;)Z" {
		t.Errorf("desc=%q", m.Descriptor)
	}
	if len(m.Calls) == 0 {
		t.Fatal("expected calls")
	}
	if m.Calls[0].Name != "equals" {
		t.Errorf("call=%q", m.Calls[0].Name)
	}
	if len(m.BasicBlocks) < 2 {
		t.Errorf("expected multiple basic blocks, got %d", len(m.BasicBlocks))
	}
	if m.ControlFlow.BranchCount < 1 {
		t.Errorf("expected branches, got %d", m.ControlFlow.BranchCount)
	}
}

func TestParseCatch(t *testing.T) {
	src := `.class public Lcom/example/T;
.method public run()V
    .locals 1
    :try_start_0
    invoke-virtual {p0}, Lcom/example/T;->work()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    return-void
    :catch_0
    move-exception v0
    throw v0
.end method
`
	ms, err := smali.Parse(src, "T.smali")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatal(len(ms))
	}
	if len(ms[0].Exceptions) != 1 {
		t.Fatalf("exceptions=%d", len(ms[0].Exceptions))
	}
	if ms[0].Exceptions[0].Type != "java.lang.Exception" {
		t.Errorf("type=%q", ms[0].Exceptions[0].Type)
	}
}
