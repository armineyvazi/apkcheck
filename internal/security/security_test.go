package security_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/security"
)

func TestSecurityTags(t *testing.T) {
	m := &ir.MethodIR{
		ClassName:  "com.example.WebViewActivity",
		MethodName: "onCreate",
		Calls: []ir.Call{
			{Owner: "android.webkit.WebView", Name: "loadUrl"},
			{Owner: "android.content.Intent", Name: "getStringExtra"},
		},
	}
	tags := security.Analyze(m)
	if len(tags) == 0 {
		t.Fatal("expected tags")
	}
	if !security.IsExportedComponentHeuristic(m.ClassName, m.MethodName) {
		t.Fatal("expected entrypoint heuristic")
	}
}
