package logcat

import "testing"

func TestDetectCrashesJava(t *testing.T) {
	raw := `01-01 00:00:00.000  1  1 E AndroidRuntime: FATAL EXCEPTION: main
01-01 00:00:00.001  1  1 E AndroidRuntime: Process: com.example.app, PID: 42
01-01 00:00:00.002  1  1 E AndroidRuntime: java.lang.NullPointerException: boom
01-01 00:00:00.003  1  1 E AndroidRuntime: 	at com.example.Foo.bar(Foo.kt:10)
01-01 00:00:00.004  1  1 E AndroidRuntime: 	at com.example.Foo.onCreate(Foo.kt:5)
`
	crashes := DetectCrashes(raw)
	if len(crashes) == 0 {
		t.Fatal("expected crash")
	}
	if crashes[0].Kind != "java" {
		t.Fatalf("kind=%s", crashes[0].Kind)
	}
	if len(crashes[0].Frames) < 1 {
		t.Fatal("frames")
	}
	if crashes[0].Frames[0].Class != "com.example.Foo" {
		t.Fatalf("%+v", crashes[0].Frames[0])
	}
}

func TestDetectANR(t *testing.T) {
	raw := `01-01 00:00:00.000  1  1 E ActivityManager: ANR in com.example.app
01-01 00:00:00.001  1  1 E ActivityManager: PID: 42
`
	crashes := DetectCrashes(raw)
	if len(crashes) == 0 {
		t.Fatal("expected ANR")
	}
}
