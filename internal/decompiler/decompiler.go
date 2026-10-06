// Package decompiler defines the interface for external Java decompilers.
package decompiler

import (
	"context"

	"github.com/armin/apkcheck/internal/ir"
)

// Input is the APK/DEX input for a decompiler run.
type Input struct {
	APKPath string
	OutDir  string
	Workers int
}

// Result is the filesystem output of a decompiler.
type Result struct {
	Name       string
	OutDir     string
	JavaRoot   string
	Version    string
	MethodIRs  []*ir.MethodIR
	Notes      []string
	Failed     bool
	FailReason string
}

// Decompiler is an external Java/Kotlin decompiler integration.
type Decompiler interface {
	Name() string
	Version(ctx context.Context) (string, error)
	Available(ctx context.Context) bool
	Decompile(ctx context.Context, input Input) (*Result, error)
}

// Paths holds optional custom binary paths.
type Paths struct {
	JADX       string
	Apktool    string
	CFR        string
	FernFlower string
	Java       string
}
