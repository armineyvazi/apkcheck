// Package instrumentation is an optional hook point (Frida, etc.).
// Default runtime remains minimally invasive — nothing runs unless enabled.
package instrumentation

import "fmt"

// Request describes an optional instrumentation backend.
type Request struct {
	Enabled  bool
	Provider string // frida | ""
}

// Validate rejects unknown providers; Frida is not auto-enabled.
func Validate(r Request) error {
	if !r.Enabled {
		return nil
	}
	switch r.Provider {
	case "frida":
		return fmt.Errorf("frida instrumentation is optional and not bundled yet — architecture seam only")
	case "":
		return fmt.Errorf("instrumentation.enabled requires provider")
	default:
		return fmt.Errorf("unknown instrumentation provider %q", r.Provider)
	}
}
