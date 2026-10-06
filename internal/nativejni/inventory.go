// Package nativejni inventories native libraries and Java↔JNI relationships.
// It does not replace Ghidra/IDA; it surfaces when control crosses into .so code.
package nativejni

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/pkg/model"
)

// Inventory builds native library entries from APK metadata and optional extracted .so paths.
func Inventory(info model.APKInfo, extractedRoot string) []model.NativeInventoryEntry {
	out := make([]model.NativeInventoryEntry, 0, len(info.NativeLibs))
	for _, lib := range info.NativeLibs {
		e := model.NativeInventoryEntry{NativeLib: lib}
		if info.SplitOrigins != nil {
			e.Split = info.SplitOrigins[lib.Path]
		}
		soPath := ""
		if extractedRoot != "" {
			cand := filepath.Join(extractedRoot, filepath.FromSlash(lib.Path))
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				soPath = cand
			}
		}
		if soPath != "" {
			syms, jni, note := readELFSymbols(soPath)
			e.ExportedSymbols = syms
			e.JNISymbols = jni
			e.Note = note
		} else {
			e.Note = "symbols not extracted; inventory from APK zip metadata only"
		}
		out = append(out, e)
	}
	return out
}

// MapJNI finds native method declarations in Smali IR and links them to libraries when possible.
func MapJNI(methods []*ir.MethodIR, libs []model.NativeInventoryEntry) []model.JNIMapping {
	libByBase := map[string]model.NativeInventoryEntry{}
	jniSymIndex := map[string]string{} // Java_pkg_Class_method → lib
	for _, l := range libs {
		libByBase[l.Name] = l
		for _, s := range l.JNISymbols {
			jniSymIndex[s] = l.Name
		}
	}

	var loadLibs []string // System.loadLibrary hints from constants
	for _, m := range methods {
		if m == nil {
			continue
		}
		for _, c := range m.Constants {
			v := c.Value
			if strings.HasPrefix(v, "lib") && strings.HasSuffix(v, ".so") {
				loadLibs = append(loadLibs, v)
			}
			// loadLibrary("foo") → libfoo.so
			if len(v) > 0 && !strings.Contains(v, "/") && !strings.Contains(v, ".") {
				cand := "lib" + v + ".so"
				if _, ok := libByBase[cand]; ok {
					loadLibs = append(loadLibs, cand)
				}
			}
		}
	}

	var out []model.JNIMapping
	for _, m := range methods {
		if m == nil {
			continue
		}
		native := false
		for _, f := range m.AccessFlags {
			if f == "native" {
				native = true
				break
			}
		}
		if !native {
			continue
		}
		mapping := model.JNIMapping{
			ClassName:  m.ClassName,
			Method:     m.MethodName,
			Descriptor: m.Descriptor,
			EClass:     model.EvidenceStatic,
			Evidence:   "Smali access flag: native",
		}
		// Standard JNI mangling: Java_com_example_Foo_bar
		mangled := jniMangle(m.ClassName, m.MethodName)
		if lib, ok := jniSymIndex[mangled]; ok {
			mapping.Library = lib
			mapping.JNISymbol = mangled
			mapping.Evidence = "ELF exported symbol matches JNI mangling"
			if e, ok := libByBase[lib]; ok {
				mapping.Split = e.Split
			}
		} else if len(loadLibs) == 1 {
			mapping.Library = loadLibs[0]
			mapping.JNISymbol = mangled
			mapping.EClass = model.EvidenceInference
			mapping.Evidence = "INFERENCE: single loadLibrary candidate; symbol not confirmed in ELF"
		} else {
			mapping.JNISymbol = mangled
			mapping.EClass = model.EvidenceUncertainty
			mapping.Evidence = "native declaration present; .so mapping unresolved"
		}
		out = append(out, mapping)
	}
	return out
}

func jniMangle(class, method string) string {
	c := strings.ReplaceAll(class, ".", "_")
	c = strings.ReplaceAll(c, "/", "_")
	c = strings.ReplaceAll(c, "$", "_00024")
	return "Java_" + c + "_" + method
}

func readELFSymbols(path string) (exported, jni []string, note string) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, fmt.Sprintf("elf open: %v", err)
	}
	defer f.Close()
	syms, err := f.DynamicSymbols()
	if err != nil {
		syms, err = f.Symbols()
		if err != nil {
			return nil, nil, "no symbol table"
		}
	}
	for _, s := range syms {
		if s.Name == "" {
			continue
		}
		if elf.ST_BIND(s.Info) == elf.STB_GLOBAL || elf.ST_BIND(s.Info) == elf.STB_WEAK {
			if len(exported) < 64 {
				exported = append(exported, s.Name)
			}
		}
		if strings.HasPrefix(s.Name, "Java_") {
			jni = append(jni, s.Name)
		}
	}
	if len(exported) == 64 {
		note = "exported symbol list truncated to 64"
	}
	return exported, jni, note
}
