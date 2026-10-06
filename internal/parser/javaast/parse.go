// Package javaast extracts a normalized MethodIR from decompiled Java source.
//
// This is intentionally pragmatic rather than a full Java language frontend:
// it focuses on method boundaries, calls, field accesses, control-flow
// constructs, and exception handlers for semantic comparison against Smali.
//
// It also handles common JADX/CFR output patterns for Kotlin-origin classes
// (Companion, DefaultImpls, suspend bridges) without claiming full Kotlin fidelity.
package javaast

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/armin/apkcheck/internal/cfg"
	"github.com/armin/apkcheck/internal/ir"
)

var (
	packageRe = regexp.MustCompile(`(?m)^\s*package\s+([\w.]+)\s*;`)
	classRe   = regexp.MustCompile(`(?m)^\s*(?:public\s+|protected\s+|private\s+|static\s+|final\s+|abstract\s+|strictfp\s+)*(?:class|interface|enum)\s+([\w$]+)`)
	// Method names may include $ for Kotlin/synthetic members. Constructors matched separately.
	methodRe = regexp.MustCompile(`(?m)^\s*(?:public\s+|protected\s+|private\s+|static\s+|final\s+|native\s+|synchronized\s+|abstract\s+|default\s+|strictfp\s+)*(?:/\*[^*]*\*/\s*)*([\w.<>,\[\]\s?]+?)\s+([\w$]+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\{`)
	ctorRe   = regexp.MustCompile(`(?m)^\s*(?:public\s+|protected\s+|private\s+)*([\w$]+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\{`)
	callRe   = regexp.MustCompile(`([\w.$]+)\s*\.\s*([\w$]+)\s*\(`)
	newRe    = regexp.MustCompile(`\bnew\s+([\w.$]+)\s*[\(\[]`)
	fieldRe  = regexp.MustCompile(`([\w.$]+)\s*\.\s*([\w$]+)\b`)
	stringRe = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
)

// ParseFile parses Java methods from a single source file.
func ParseFile(path string, source ir.SourceKind) ([]*ir.MethodIR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read java %s: %w", path, err)
	}
	return Parse(string(data), path, source)
}

// ParseDir walks a directory tree of .java files.
// Per-file errors are skipped so one malformed file cannot abort analysis.
func ParseDir(root string, source ir.SourceKind) ([]*ir.MethodIR, error) {
	var all []*ir.MethodIR
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".java") {
			return nil
		}
		ms, err := ParseFile(path, source)
		if err != nil {
			return nil
		}
		all = append(all, ms...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk java dir: %w", err)
	}
	return all, nil
}

// Parse extracts methods from Java source text.
func Parse(src, path string, source ir.SourceKind) ([]*ir.MethodIR, error) {
	pkg := ""
	if m := packageRe.FindStringSubmatch(src); len(m) == 2 {
		pkg = m[1]
	}
	class := ""
	if m := classRe.FindStringSubmatch(src); len(m) == 2 {
		class = m[1]
	}
	className := class
	if pkg != "" && class != "" {
		className = pkg + "." + class
	}

	kotlinHints := detectKotlinHints(src, className)

	seen := map[string]bool{}
	var methods []*ir.MethodIR

	add := func(name, retType, paramsRaw, body string) {
		key := name + "|" + paramsRaw + "|" + retType
		if seen[key] {
			return
		}
		seen[key] = true
		params := parseParams(paramsRaw)
		m := &ir.MethodIR{
			ClassName:  className,
			MethodName: name,
			Descriptor: synthesizeDescriptor(params, retType),
			Parameters: params,
			ReturnType: ir.Type(normalizeType(retType)),
			Source:     source,
			SourcePath: path,
			RawSource:  body,
		}
		if kotlinHints {
			m.AccessFlags = append(m.AccessFlags, "kotlin-origin")
		}
		analyzeBody(m, body)
		cfg.Build(m)
		methods = append(methods, m)
	}

	for _, loc := range methodRe.FindAllStringSubmatchIndex(src, -1) {
		retType := strings.TrimSpace(src[loc[2]:loc[3]])
		name := src[loc[4]:loc[5]]
		paramsRaw := src[loc[6]:loc[7]]
		if isKeyword(name) {
			continue
		}
		bodyStart := loc[1] - 1
		body, ok := extractBlock(src, bodyStart)
		if !ok {
			continue
		}
		add(name, retType, paramsRaw, body)
	}

	// Constructors: ClassName(...) {
	for _, loc := range ctorRe.FindAllStringSubmatchIndex(src, -1) {
		ctorName := src[loc[2]:loc[3]]
		if class == "" || ctorName != class {
			continue
		}
		paramsRaw := src[loc[4]:loc[5]]
		bodyStart := loc[1] - 1
		body, ok := extractBlock(src, bodyStart)
		if !ok {
			continue
		}
		add("<init>", "void", paramsRaw, body)
	}

	return methods, nil
}

func detectKotlinHints(src, className string) bool {
	if strings.Contains(src, "kotlin.Metadata") || strings.Contains(src, "kotlin/Metadata") {
		return true
	}
	if strings.Contains(src, "kotlin.jvm.internal") || strings.Contains(src, "kotlin.coroutines") {
		return true
	}
	if strings.HasSuffix(className, "Kt") || strings.Contains(className, "Companion") {
		return true
	}
	if strings.Contains(className, "DefaultImpls") || strings.Contains(src, "Intrinsics.check") {
		return true
	}
	return false
}

func analyzeBody(m *ir.MethodIR, body string) {
	stripped := stringRe.ReplaceAllStringFunc(body, func(s string) string {
		m.Constants = append(m.Constants, ir.Constant{Kind: "string", Value: s})
		return `""`
	})

	lines := strings.Split(stripped, "\n")
	idx := 0
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "import ") {
			continue
		}
		op, _ := classifyJavaLine(trim)
		ins := ir.Instruction{
			Index:    idx,
			Opcode:   op,
			Operands: []string{trim},
		}
		if strings.HasPrefix(trim, "case ") || strings.HasPrefix(trim, "default:") {
			ins.Label = "case_" + fmt.Sprint(idx)
		}
		m.Instructions = append(m.Instructions, ins)
		idx++

		m.Calls = append(m.Calls, extractCalls(trim)...)
		if op == "new" {
			if mm := newRe.FindStringSubmatch(trim); len(mm) == 2 {
				m.Calls = append(m.Calls, ir.Call{
					InvokeKind: "new",
					Owner:      mm[1],
					Name:       "<init>",
				})
			}
		}
		if op == "catch" {
			m.Exceptions = append(m.Exceptions, ir.ExceptionHandler{
				Type: extractCatchType(trim),
			})
		}
		m.FieldAccesses = append(m.FieldAccesses, extractFields(trim)...)
	}
	linkJavaBranches(m)
}

func classifyJavaLine(line string) (opcode string, targets []string) {
	switch {
	case strings.HasPrefix(line, "if ") || strings.HasPrefix(line, "if("):
		return "if", nil
	case strings.HasPrefix(line, "else if") || strings.HasPrefix(line, "} else if"):
		return "if", nil
	case strings.HasPrefix(line, "else") || strings.HasPrefix(line, "} else"):
		return "else", nil
	case strings.HasPrefix(line, "for ") || strings.HasPrefix(line, "for("):
		return "if", nil
	case strings.HasPrefix(line, "while ") || strings.HasPrefix(line, "while("):
		return "if", nil
	case strings.HasPrefix(line, "do ") || line == "do" || strings.HasPrefix(line, "do{"):
		return "if", nil
	case strings.HasPrefix(line, "switch ") || strings.HasPrefix(line, "switch("):
		return "switch", nil
	case strings.HasPrefix(line, "return"):
		return "return", nil
	case strings.HasPrefix(line, "throw "):
		return "throw", nil
	case strings.HasPrefix(line, "try") || strings.HasPrefix(line, "try "):
		return "try", nil
	case strings.HasPrefix(line, "catch ") || strings.HasPrefix(line, "} catch"):
		return "catch", nil
	case strings.HasPrefix(line, "finally") || strings.HasPrefix(line, "} finally"):
		return "finally", nil
	case strings.HasPrefix(line, "synchronized ") || strings.HasPrefix(line, "synchronized("):
		return "monitor-enter", nil
	case strings.Contains(line, "new "):
		return "new", nil
	case strings.Contains(line, "(") && strings.Contains(line, ")"):
		return "invoke", nil
	default:
		return "stmt", nil
	}
}

func linkJavaBranches(m *ir.MethodIR) {
	for i := range m.Instructions {
		ins := &m.Instructions[i]
		if ins.Label == "" {
			ins.Label = fmt.Sprintf("L%d", i)
		}
		switch ins.Opcode {
		case "if":
			if i+1 < len(m.Instructions) {
				ins.Targets = []string{fmt.Sprintf("L%d", i+1)}
			}
		case "switch":
			var tgts []string
			for j := i + 1; j < len(m.Instructions) && j < i+20; j++ {
				if strings.HasPrefix(m.Instructions[j].Label, "case_") {
					tgts = append(tgts, m.Instructions[j].Label)
				}
				if m.Instructions[j].Opcode == "return" || m.Instructions[j].Opcode == "throw" {
					break
				}
			}
			ins.Targets = tgts
		}
	}
}

func extractCalls(line string) []ir.Call {
	var out []ir.Call
	for _, m := range callRe.FindAllStringSubmatch(line, -1) {
		owner := m[1]
		name := m[2]
		if isKeyword(owner) || isKeyword(name) {
			continue
		}
		out = append(out, ir.Call{
			InvokeKind: "invoke",
			Owner:      owner,
			Name:       name,
		})
	}
	return out
}

func extractFields(line string) []ir.FieldAccess {
	var out []ir.FieldAccess
	tmp := callRe.ReplaceAllString(line, "")
	for _, m := range fieldRe.FindAllStringSubmatch(tmp, -1) {
		owner, name := m[1], m[2]
		if isKeyword(owner) || isKeyword(name) || strings.Contains(owner, "(") {
			continue
		}
		kind := "get"
		if strings.Contains(line, name+" =") || strings.Contains(line, name+"=") {
			kind = "put"
		}
		out = append(out, ir.FieldAccess{Kind: kind, Owner: owner, Name: name})
	}
	return out
}

func extractCatchType(line string) string {
	start := strings.Index(line, "(")
	end := strings.Index(line, ")")
	if start < 0 || end <= start {
		return "any"
	}
	inside := strings.TrimSpace(line[start+1 : end])
	fields := strings.Fields(inside)
	if len(fields) >= 1 {
		return normalizeType(fields[0])
	}
	return "any"
}

func parseParams(raw string) []ir.Type {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := splitParams(raw)
	out := make([]ir.Type, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fields := strings.Fields(p)
		if len(fields) >= 1 {
			out = append(out, ir.Type(normalizeType(fields[0])))
		}
	}
	return out
}

func splitParams(raw string) []string {
	var parts []string
	depth := 0
	start := 0
	for i, r := range raw {
		switch r {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, raw[start:])
	return parts
}

func synthesizeDescriptor(params []ir.Type, ret string) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, p := range params {
		b.WriteString(string(p))
		b.WriteByte(';')
	}
	b.WriteByte(')')
	b.WriteString(normalizeType(ret))
	return b.String()
}

func normalizeType(t string) string {
	t = strings.TrimSpace(t)
	t = strings.ReplaceAll(t, " ", "")
	if i := strings.Index(t, "<"); i >= 0 {
		t = t[:i]
	}
	return t
}

func extractBlock(src string, braceIdx int) (string, bool) {
	if braceIdx < 0 || braceIdx >= len(src) || src[braceIdx] != '{' {
		return "", false
	}
	depth := 0
	inStr := false
	inChar := false
	escape := false
	for i := braceIdx; i < len(src); i++ {
		c := src[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && (inStr || inChar) {
			escape = true
			continue
		}
		if c == '"' && !inChar {
			inStr = !inStr
			continue
		}
		if c == '\'' && !inStr {
			inChar = !inChar
			continue
		}
		if inStr || inChar {
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return src[braceIdx+1 : i], true
			}
		}
	}
	return "", false
}

func isKeyword(s string) bool {
	switch s {
	case "if", "for", "while", "switch", "return", "throw", "new", "this",
		"super", "class", "true", "false", "null", "else", "try", "catch",
		"finally", "case", "default", "break", "continue", "instanceof",
		"synchronized", "assert", "var", "void", "int", "long", "boolean",
		"byte", "short", "char", "float", "double", "public", "private",
		"protected", "static", "final", "import", "package", "extends",
		"implements", "interface", "enum", "record":
		return true
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '$' && r != '.' {
			return true
		}
	}
	return false
}
