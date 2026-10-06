// Package androidx provides Android / Kotlin classification helpers used to
// focus analysis on app code rather than framework noise.
package androidx

import "strings"

// IsFrameworkPackage reports packages that are usually library/framework noise
// for app-centric reverse engineering.
func IsFrameworkPackage(className string) bool {
	c := strings.ToLower(strings.ReplaceAll(className, "/", "."))
	prefixes := []string{
		"android.",
		"androidx.",
		"com.google.android.",
		"com.android.",
		"java.",
		"javax.",
		"jdk.",
		"kotlin.",
		"kotlinx.",
		"dalvik.",
		"org.apache.http.",
		"org.json.",
		"org.xml.",
		"org.xmlpull.",
		"org.w3c.",
		"okhttp3.",
		"okio.",
		"retrofit2.",
		"com.squareup.",
		"io.reactivex.",
		"reactor.",
		"com.fasterxml.",
		"org.intellij.",
		"org.jetbrains.annotations.",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

// IsKotlinSynthetic reports common Kotlin-generated method/class name patterns.
func IsKotlinSynthetic(className, methodName string) bool {
	if strings.Contains(className, "Kt$") || strings.HasSuffix(className, "Kt") {
		return true
	}
	if strings.Contains(className, "$") && (strings.Contains(className, "$coroutine") ||
		strings.Contains(className, "$inlined") ||
		strings.Contains(className, "$sam$") ||
		strings.Contains(className, "WhenMappings")) {
		return true
	}
	switch {
	case strings.HasPrefix(methodName, "access$"):
		return true
	case strings.HasPrefix(methodName, "$r8$"):
		return true
	case methodName == "create" && strings.Contains(className, "Continuation"):
		return true
	case methodName == "invokeSuspend":
		return true
	case methodName == "<clinit>":
		return false // still useful for static init review
	}
	return false
}

// IsKotlinCoroutineContinuation detects coroutine state-machine classes.
func IsKotlinCoroutineContinuation(className string) bool {
	c := className
	return strings.Contains(c, "$coroutine") ||
		strings.Contains(c, "ContinuationImpl") ||
		strings.HasSuffix(c, "Continuation")
}

// NormalizeClassName converts slash or dot forms to canonical dotted form.
func NormalizeClassName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "/", ".")
	name = strings.TrimPrefix(name, "L")
	name = strings.TrimSuffix(name, ";")
	return name
}

// LooksLikeAppPackage is a weak heuristic: not framework and has ≥3 segments.
func LooksLikeAppPackage(className string) bool {
	c := NormalizeClassName(className)
	if IsFrameworkPackage(c) {
		return false
	}
	return strings.Count(c, ".") >= 2
}
