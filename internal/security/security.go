// Package security identifies methods that may be relevant to security review.
// Presence of a pattern does NOT imply a vulnerability.
package security

import (
	"strings"

	"github.com/armin/apkcheck/internal/ir"
)

// Tag describes a security-relevant pattern.
type Tag struct {
	Name string
	Why  string
}

var callPatterns = []struct {
	substr string
	tag    string
	why    string
}{
	{"getIntent", "intent_input", "reads Intent extras / data"},
	{"getStringExtra", "intent_input", "reads string Intent extra"},
	{"getQueryParameter", "deeplink", "URI query parameter access"},
	{"loadUrl", "webview", "WebView URL load"},
	{"evaluateJavascript", "webview", "WebView JavaScript evaluation"},
	{"addJavascriptInterface", "webview", "JavaScript bridge"},
	{"openFileInput", "file_access", "internal file read"},
	{"openFileOutput", "file_access", "internal file write"},
	{"getExternalStorage", "file_access", "external storage access"},
	{"getContentResolver", "content_provider", "ContentResolver access"},
	{"query(", "content_provider", "content/SQL query"},
	{"rawQuery", "sql", "raw SQL query"},
	{"execSQL", "sql", "SQL execution"},
	{"Runtime.getRuntime", "command_exec", "runtime access"},
	{"exec(", "command_exec", "process execution"},
	{"loadClass", "dynamic_code", "dynamic class loading"},
	{"DexClassLoader", "dynamic_code", "DEX class loader"},
	{"PathClassLoader", "dynamic_code", "path class loader"},
	{"getMethod", "reflection", "reflective method lookup"},
	{"invoke(", "reflection", "reflective invoke"},
	{"Cipher", "crypto", "cryptographic API"},
	{"MessageDigest", "crypto", "message digest"},
	{"SecretKey", "crypto", "secret key usage"},
	{"HttpsURLConnection", "network", "HTTPS connection"},
	{"OkHttp", "network", "HTTP client"},
	{"openConnection", "network", "URL connection"},
	{"SharedPreferences", "sensitive_storage", "shared preferences"},
	{"getSharedPreferences", "sensitive_storage", "shared preferences"},
	{"Parcelable", "ipc", "Parcelable IPC"},
	{"Binder", "binder", "Binder IPC"},
	{"transact", "binder", "Binder transaction"},
	{"ObjectInputStream", "deserialization", "Java deserialization"},
	{"readObject", "deserialization", "object deserialization"},
	{"System.loadLibrary", "native", "native library load"},
	{"native ", "native", "native method"},
	{"authenticate", "auth", "authentication-related symbol"},
	{"authorize", "authz", "authorization-related symbol"},
	{"password", "auth", "password-related symbol"},
	{"token", "auth", "token-related symbol"},
	{"invokeSuspend", "kotlin_coroutine", "Kotlin coroutine state machine"},
	{"withContext", "kotlin_coroutine", "Kotlin coroutine dispatcher switch"},
	{"viewModelScope", "kotlin_coroutine", "Android ViewModel coroutine scope"},
	{"lifecycleScope", "kotlin_coroutine", "Android lifecycle coroutine scope"},
	{"EncryptedSharedPreferences", "sensitive_storage", "encrypted preferences"},
	{"MasterKey", "crypto", "AndroidX security crypto"},
	{"BiometricPrompt", "auth", "biometric authentication"},
	{"setJavaScriptEnabled", "webview", "WebView JS enable"},
	{"setAllowFileAccess", "webview", "WebView file access"},
	{"getSerializableExtra", "deserialization", "Intent serializable extra"},
	{"getParcelableExtra", "ipc", "Intent parcelable extra"},
	{"startActivityForResult", "intent_input", "activity result flow"},
	{"registerReceiver", "ipc", "broadcast receiver registration"},
	{"PendingIntent", "ipc", "PendingIntent usage"},
	{"ClipboardManager", "sensitive_storage", "clipboard access"},
	{"Log.d", "logging", "debug logging (possible secret leak)"},
	{"Log.e", "logging", "error logging"},
}

var classPatterns = []struct {
	substr string
	tag    string
}{
	{"WebView", "webview"},
	{"DeepLink", "deeplink"},
	{"Auth", "auth"},
	{"Login", "auth"},
	{"Crypto", "crypto"},
	{"Cipher", "crypto"},
	{"Provider", "content_provider"},
	{"Receiver", "ipc"},
}

// Analyze returns security tags for a method. Empty means not prioritized.
func Analyze(m *ir.MethodIR) []string {
	if m == nil {
		return nil
	}
	tags := map[string]struct{}{}

	for _, p := range classPatterns {
		if strings.Contains(m.ClassName, p.substr) || strings.Contains(m.MethodName, p.substr) {
			tags[p.tag] = struct{}{}
		}
	}

	hay := strings.ToLower(m.MethodName + " " + m.ClassName)
	for _, c := range m.Calls {
		hay += " " + strings.ToLower(c.Owner+"."+c.Name)
	}
	for _, c := range m.Constants {
		if c.Kind == "string" {
			hay += " " + strings.ToLower(c.Value)
		}
	}
	for _, p := range callPatterns {
		if strings.Contains(hay, strings.ToLower(p.substr)) {
			tags[p.tag] = struct{}{}
		}
	}

	out := make([]string, 0, len(tags))
	for t := range tags {
		out = append(out, t)
	}
	return out
}

// IsExportedComponentHeuristic flags common entrypoints.
func IsExportedComponentHeuristic(class, method string) bool {
	switch method {
	case "onCreate", "onStart", "onResume", "onReceive", "onBind",
		"onHandleIntent", "onHandleWork", "attachBaseContext":
		return true
	}
	return false
}
