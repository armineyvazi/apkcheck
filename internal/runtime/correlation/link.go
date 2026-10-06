// Package correlation maps runtime stack frames to static DEX/Smali/decompiler evidence.
package correlation

import (
	"strings"

	"github.com/armin/apkcheck/internal/runtime/logcat"
	"github.com/armin/apkcheck/pkg/model"
)

// MethodLink is a partial or full correlation result.
type MethodLink struct {
	RuntimeClass  string `json:"runtime_class"`
	RuntimeMethod string `json:"runtime_method"`
	StaticClass   string `json:"static_class,omitempty"`
	StaticMethod  string `json:"static_method,omitempty"`
	Descriptor    string `json:"descriptor,omitempty"`
	Status        string `json:"status"` // CORRELATED | PARTIAL_CORRELATION | UNRESOLVED
	EvidenceClass string `json:"evidence_class"`
	Note          string `json:"note,omitempty"`
}

// LinkCrashFrames attempts to map crash frames onto static method results.
func LinkCrashFrames(frames []logcat.Frame, methods []model.MethodResult) []MethodLink {
	idx := map[string]model.MethodResult{}
	for _, m := range methods {
		key := strings.ToLower(m.Ref.Class) + "->" + m.Ref.Name
		idx[key] = m
		// also short class
		if i := strings.LastIndex(m.Ref.Class, "."); i >= 0 {
			idx[strings.ToLower(m.Ref.Class[i+1:])+"->"+m.Ref.Name] = m
		}
	}
	var out []MethodLink
	seen := map[string]bool{}
	for _, fr := range frames {
		if fr.Class == "" || fr.Method == "" {
			continue
		}
		if strings.HasPrefix(fr.Class, "android.") || strings.HasPrefix(fr.Class, "java.") ||
			strings.HasPrefix(fr.Class, "kotlin.") || strings.HasPrefix(fr.Class, "dalvik.") {
			continue
		}
		key := strings.ToLower(fr.Class) + "->" + fr.Method
		if seen[key] {
			continue
		}
		seen[key] = true
		link := MethodLink{
			RuntimeClass: fr.Class, RuntimeMethod: fr.Method,
			EvidenceClass: "INFERENCE",
		}
		if m, ok := idx[key]; ok {
			link.StaticClass = m.Ref.Class
			link.StaticMethod = m.Ref.Name
			link.Descriptor = m.Ref.Descriptor
			link.Status = "CORRELATED"
			link.EvidenceClass = "STATIC_AND_RUNTIME_CORRELATED"
			link.Note = "Runtime frame matched static method by class+name. Descriptor ambiguity possible under overloads."
		} else if m, ok := idx[strings.ToLower(short(fr.Class))+"->"+fr.Method]; ok {
			link.StaticClass = m.Ref.Class
			link.StaticMethod = m.Ref.Name
			link.Descriptor = m.Ref.Descriptor
			link.Status = "PARTIAL_CORRELATION"
			link.Note = "Matched by short class name + method only."
		} else {
			link.Status = "UNRESOLVED"
			link.Note = "No static method match found for this frame (obfuscation, not analyzed, or not present)."
		}
		out = append(out, link)
	}
	return out
}

func short(c string) string {
	if i := strings.LastIndex(c, "."); i >= 0 {
		return c[i+1:]
	}
	return c
}
