// Package smali parses Smali source into MethodIR (DEX ground truth).
package smali

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/armin/apkcheck/internal/cfg"
	"github.com/armin/apkcheck/internal/ir"
)

// ParseFile parses a single .smali file into zero or more methods.
func ParseFile(path string) ([]*ir.MethodIR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read smali %s: %w", path, err)
	}
	return Parse(string(data), path)
}

// Parse parses Smali source text.
func Parse(src, path string) ([]*ir.MethodIR, error) {
	className := ""
	var methods []*ir.MethodIR
	lines := splitLines(src)

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, ".class") {
			className = parseClassName(line)
			continue
		}
		if strings.HasPrefix(line, ".method") {
			m, next, err := parseMethod(lines, i, className, path)
			if err != nil {
				return methods, err
			}
			methods = append(methods, m)
			i = next
		}
	}
	return methods, nil
}

// ParseDir recursively parses all .smali files under root.
// Individual file parse errors are collected; the walk continues.
func ParseDir(root string) ([]*ir.MethodIR, error) {
	var all []*ir.MethodIR
	var firstErr error
	errCount := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".smali") {
			return nil
		}
		ms, err := ParseFile(path)
		if err != nil {
			errCount++
			if firstErr == nil {
				firstErr = err
			}
			return nil // continue: one bad file must not abort the APK analysis
		}
		all = append(all, ms...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk smali dir: %w", err)
	}
	if len(all) == 0 && firstErr != nil {
		return nil, fmt.Errorf("parse smali: %w", firstErr)
	}
	return all, nil
}

func parseClassName(line string) string {
	// .class public Lcom/example/Foo;
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	desc := fields[len(fields)-1]
	return descriptorToClass(desc)
}

func parseMethod(lines []string, start int, className, path string) (*ir.MethodIR, int, error) {
	header := strings.TrimSpace(lines[start])
	// .method public authenticate(Ljava/lang/String;)Z
	rest := strings.TrimSpace(strings.TrimPrefix(header, ".method"))
	parts := strings.Fields(rest)
	access := []string{}
	sig := ""
	for _, p := range parts {
		if strings.Contains(p, "(") {
			sig = p
			break
		}
		access = append(access, p)
	}
	name, desc := splitNameDesc(sig)
	params, ret := parseDescriptor(desc)

	m := &ir.MethodIR{
		ClassName:   className,
		MethodName:  name,
		Descriptor:  desc,
		Parameters:  params,
		ReturnType:  ret,
		AccessFlags: access,
		Source:      ir.SourceSmali,
		SourcePath:  path,
	}

	i := start + 1
	instrIndex := 0
	for ; i < len(lines); i++ {
		raw := lines[i]
		line := strings.TrimSpace(raw)
		if line == ".end method" {
			break
		}
		if line == "" || strings.HasPrefix(line, ".locals") || strings.HasPrefix(line, ".registers") ||
			strings.HasPrefix(line, ".param") || strings.HasPrefix(line, ".line") ||
			strings.HasPrefix(line, ".prologue") || strings.HasPrefix(line, ".end local") ||
			strings.HasPrefix(line, ".local") || strings.HasPrefix(line, ".restart local") ||
			strings.HasPrefix(line, ".array-data") || strings.HasPrefix(line, ".end array-data") ||
			strings.HasPrefix(line, ".annotation") || strings.HasPrefix(line, ".end annotation") ||
			strings.HasPrefix(line, ".subannotation") || strings.HasPrefix(line, ".end subannotation") {
			continue
		}
		if strings.HasPrefix(line, ".catch") || strings.HasPrefix(line, ".catchall") {
			m.Exceptions = append(m.Exceptions, parseCatch(line))
			continue
		}
		// packed-switch / sparse-switch payload blocks
		if strings.HasPrefix(line, ".packed-switch") || strings.HasPrefix(line, ".sparse-switch") {
			for i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), ".end") {
				i++
			}
			if i+1 < len(lines) {
				i++ // skip .end *
			}
			continue
		}

		ins := parseInstruction(line, instrIndex)
		if ins.Opcode == "" && ins.Label == "" {
			continue
		}
		// Label-only line: attach to the next real instruction instead of
		// creating an empty-opcode CFG block (cleaner ground-truth graphs).
		if ins.Opcode == "" && ins.Label != "" {
			pendingLabel := ins.Label
			attached := false
			for j := i + 1; j < len(lines); j++ {
				nline := strings.TrimSpace(lines[j])
				if nline == "" || strings.HasPrefix(nline, "#") {
					continue
				}
				// Directives must stay visible to the outer loop (.catch, .end method, …).
				if strings.HasPrefix(nline, ".") {
					break
				}
				if strings.HasPrefix(nline, ":") {
					break
				}
				next := parseInstruction(nline, instrIndex)
				if pendingLabel != "" && next.Label == "" {
					next.Label = pendingLabel
				}
				classifySideEffects(m, next)
				m.Instructions = append(m.Instructions, next)
				instrIndex++
				i = j
				attached = true
				break
			}
			if !attached {
				m.Instructions = append(m.Instructions, ir.Instruction{Index: instrIndex, Label: pendingLabel})
				instrIndex++
			}
			continue
		}
		classifySideEffects(m, ins)
		m.Instructions = append(m.Instructions, ins)
		instrIndex++
	}

	cfg.Build(m)
	return m, i, nil
}

func parseInstruction(line string, index int) ir.Instruction {
	ins := ir.Instruction{Index: index}

	// Label:  :cond_0  or  :goto_0
	if strings.HasPrefix(line, ":") {
		lab := strings.Fields(line)[0]
		ins.Label = strings.TrimPrefix(lab, ":")
		rest := strings.TrimSpace(strings.TrimPrefix(line, lab))
		if rest == "" {
			return ins
		}
		line = rest
	}

	// Strip trailing comments
	if idx := strings.Index(line, "#"); idx >= 0 {
		ins.Comment = strings.TrimSpace(line[idx+1:])
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return ins
	}

	fields := tokenize(line)
	if len(fields) == 0 {
		return ins
	}
	ins.Opcode = fields[0]
	ins.Operands = fields[1:]

	switch {
	case strings.HasPrefix(ins.Opcode, "if-"), ins.Opcode == "goto", strings.HasPrefix(ins.Opcode, "goto/"):
		for _, op := range ins.Operands {
			if strings.HasPrefix(op, ":") {
				ins.Targets = append(ins.Targets, strings.TrimPrefix(op, ":"))
			}
		}
	case ins.Opcode == "packed-switch", ins.Opcode == "sparse-switch":
		for _, op := range ins.Operands {
			if strings.HasPrefix(op, ":") {
				ins.Targets = append(ins.Targets, strings.TrimPrefix(op, ":"))
			}
		}
	}
	return ins
}

func classifySideEffects(m *ir.MethodIR, ins ir.Instruction) {
	op := ins.Opcode
	switch {
	case strings.HasPrefix(op, "invoke-"):
		owner, name, desc := parseInvokeTarget(ins.Operands)
		m.Calls = append(m.Calls, ir.Call{
			InvokeKind: op,
			Owner:      owner,
			Name:       name,
			Descriptor: desc,
		})
	case strings.HasPrefix(op, "iget"), strings.HasPrefix(op, "sget"),
		strings.HasPrefix(op, "iput"), strings.HasPrefix(op, "sput"):
		kind := "get"
		if strings.Contains(op, "put") {
			kind = "put"
		}
		owner, name, typ := parseFieldTarget(ins.Operands)
		m.FieldAccesses = append(m.FieldAccesses, ir.FieldAccess{
			Kind:  kind,
			Owner: owner,
			Name:  name,
			Type:  typ,
		})
	case op == "const-string", op == "const-string/jumbo":
		if len(ins.Operands) >= 2 {
			m.Constants = append(m.Constants, ir.Constant{
				Kind:  "string",
				Value: strings.Join(ins.Operands[1:], " "),
			})
		}
	case strings.HasPrefix(op, "const"):
		if len(ins.Operands) >= 2 {
			m.Constants = append(m.Constants, ir.Constant{
				Kind:  "number",
				Value: ins.Operands[len(ins.Operands)-1],
			})
		}
	}
}

func parseCatch(line string) ir.ExceptionHandler {
	// .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
	// .catchall {:try_start_0 .. :try_end_0} :catch_0
	h := ir.ExceptionHandler{Type: "any"}
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.HasPrefix(fields[1], "L") {
		h.Type = descriptorToClass(fields[1])
	}
	for _, f := range fields {
		f = strings.Trim(f, "{}")
		if strings.HasPrefix(f, ":try_start") || strings.HasPrefix(f, ":try_") {
			if h.StartLabel == "" && strings.Contains(f, "start") {
				h.StartLabel = strings.TrimPrefix(f, ":")
			}
		}
		if strings.Contains(f, "try_end") || strings.HasSuffix(f, "_end") {
			h.EndLabel = strings.TrimPrefix(f, ":")
		}
		if strings.HasPrefix(f, ":catch") || strings.HasPrefix(f, ":catchall") {
			h.Handler = strings.TrimPrefix(f, ":")
		}
	}
	// More reliable parse using braces
	if i := strings.Index(line, "{"); i >= 0 {
		j := strings.Index(line[i:], "}")
		if j >= 0 {
			inside := line[i+1 : i+j]
			inside = strings.ReplaceAll(inside, "..", " ")
			parts := strings.Fields(inside)
			if len(parts) >= 1 {
				h.StartLabel = strings.TrimPrefix(parts[0], ":")
			}
			if len(parts) >= 2 {
				h.EndLabel = strings.TrimPrefix(parts[1], ":")
			}
		}
		rest := strings.TrimSpace(line[i+j+1:])
		if rest != "" {
			h.Handler = strings.TrimPrefix(strings.Fields(rest)[0], ":")
		}
	}
	return h
}

func parseInvokeTarget(operands []string) (owner, name, desc string) {
	// invoke-virtual {v0, v1}, Lcom/example/Foo;->bar(Ljava/lang/String;)V
	for _, op := range operands {
		if strings.Contains(op, "->") {
			return splitMember(op)
		}
	}
	return "", "", ""
}

func parseFieldTarget(operands []string) (owner, name, typ string) {
	for _, op := range operands {
		if strings.Contains(op, "->") {
			o, n, d := splitMember(op)
			return o, n, d
		}
	}
	return "", "", ""
}

func splitMember(s string) (owner, name, desc string) {
	// Lcom/example/Foo;->bar(Ljava/lang/String;)V
	// Lcom/example/Foo;->field:I
	s = strings.TrimSuffix(s, ",")
	parts := strings.SplitN(s, "->", 2)
	if len(parts) != 2 {
		return "", "", ""
	}
	owner = descriptorToClass(parts[0])
	rhs := parts[1]
	if i := strings.IndexAny(rhs, "(:"); i >= 0 {
		name = rhs[:i]
		desc = strings.TrimPrefix(rhs[i:], ":")
	} else {
		name = rhs
	}
	return owner, name, desc
}

func splitNameDesc(sig string) (name, desc string) {
	i := strings.Index(sig, "(")
	if i < 0 {
		return sig, ""
	}
	return sig[:i], sig[i:]
}

func parseDescriptor(desc string) (params []ir.Type, ret ir.Type) {
	if desc == "" || !strings.HasPrefix(desc, "(") {
		return nil, ""
	}
	end := strings.Index(desc, ")")
	if end < 0 {
		return nil, ""
	}
	paramPart := desc[1:end]
	ret = ir.Type(descriptorToClass(desc[end+1:]))
	for len(paramPart) > 0 {
		t, rest := readType(paramPart)
		params = append(params, ir.Type(t))
		paramPart = rest
	}
	return params, ret
}

func readType(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	switch s[0] {
	case 'V':
		return "void", s[1:]
	case 'Z':
		return "boolean", s[1:]
	case 'B':
		return "byte", s[1:]
	case 'S':
		return "short", s[1:]
	case 'C':
		return "char", s[1:]
	case 'I':
		return "int", s[1:]
	case 'J':
		return "long", s[1:]
	case 'F':
		return "float", s[1:]
	case 'D':
		return "double", s[1:]
	case '[':
		inner, rest := readType(s[1:])
		return inner + "[]", rest
	case 'L':
		semi := strings.IndexByte(s, ';')
		if semi < 0 {
			return s, ""
		}
		return descriptorToClass(s[:semi+1]), s[semi+1:]
	default:
		return string(s[0]), s[1:]
	}
}

func descriptorToClass(desc string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return ""
	}
	if strings.HasPrefix(desc, "L") && strings.HasSuffix(desc, ";") {
		return strings.ReplaceAll(desc[1:len(desc)-1], "/", ".")
	}
	switch desc {
	case "V":
		return "void"
	case "Z":
		return "boolean"
	case "B":
		return "byte"
	case "S":
		return "short"
	case "C":
		return "char"
	case "I":
		return "int"
	case "J":
		return "long"
	case "F":
		return "float"
	case "D":
		return "double"
	}
	if strings.HasPrefix(desc, "[") {
		t, _ := readType(desc)
		return t
	}
	return strings.ReplaceAll(desc, "/", ".")
}

func tokenize(line string) []string {
	var out []string
	var b strings.Builder
	inBrace := 0
	inQuote := false
	for _, r := range line {
		switch {
		case r == '"' && inBrace == 0:
			inQuote = !inQuote
			b.WriteRune(r)
		case inQuote:
			b.WriteRune(r)
		case r == '{':
			inBrace++
			b.WriteRune(r)
		case r == '}':
			inBrace--
			b.WriteRune(r)
		case unicode.IsSpace(r) && inBrace == 0:
			if b.Len() > 0 {
				out = append(out, strings.TrimSuffix(b.String(), ","))
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, strings.TrimSuffix(b.String(), ","))
	}
	return out
}

func splitLines(s string) []string {
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}
