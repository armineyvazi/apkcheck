package permissions

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		in   Status
		want string
	}{
		{"all", Status{DeclaredStatic: true, GrantedRuntime: true, ObservedUsage: true}, "STATIC_AND_RUNTIME_CORRELATED"},
		{"declared_granted", Status{DeclaredStatic: true, GrantedRuntime: true}, "RUNTIME_OBSERVED"},
		{"declared_only", Status{DeclaredStatic: true}, "STATIC_CONFIRMED"},
		{"granted_only", Status{GrantedRuntime: true}, "RUNTIME_OBSERVED"},
		{"none", Status{}, "NOT_OBSERVED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, conc := classify(tt.in)
			if got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
			if conc == "" {
				t.Fatal("empty conclusion")
			}
		})
	}
}

func TestParseGranted(t *testing.T) {
	dump := `
Package [com.example]
    requested permissions:
      android.permission.INTERNET
    install permissions:
      android.permission.INTERNET: granted=true
    runtime permissions:
      android.permission.CAMERA: granted=true
`
	g := parseGranted(dump)
	if !g["android.permission.INTERNET"] || !g["android.permission.CAMERA"] {
		t.Fatalf("%v", g)
	}
}
