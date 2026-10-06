// Package versioned runs pinned decompiler versions (local or Docker).
package versioned

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/decompiler/cfr"
	"github.com/armin/apkcheck/internal/decompiler/fernflower"
	"github.com/armin/apkcheck/internal/decompiler/jadx"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/parser/javaast"
	"github.com/armin/apkcheck/internal/registry"
	"github.com/armin/apkcheck/internal/runner"
)

// Instance is one pinned decompiler version ready to run.
type Instance struct {
	Tool     string
	Pin      registry.PinnedVersion
	Identity registry.ToolIdentity
	inner    decompiler.Decompiler
	docker   bool
	image    string
	javaPath string
}

// Key returns a stable report key like "jadx@1.5.6".
func (i *Instance) Key() string {
	return i.Tool + "@" + i.Pin.ID
}

func (i *Instance) Name() string { return i.Key() }

func (i *Instance) Version(ctx context.Context) (string, error) {
	return i.Pin.ID, nil
}

func (i *Instance) Available(ctx context.Context) bool {
	if i.docker {
		_, err := runner.LookPath("", "docker")
		return err == nil && i.image != ""
	}
	if i.inner != nil {
		return i.inner.Available(ctx)
	}
	return false
}

func (i *Instance) Decompile(ctx context.Context, input decompiler.Input) (*decompiler.Result, error) {
	outBase := filepath.Join(input.OutDir, "versions", i.Tool, sanitize(i.Pin.ID))
	if err := os.MkdirAll(outBase, 0o750); err != nil {
		return nil, err
	}
	in := input
	in.OutDir = outBase

	if i.docker {
		return i.decompileDocker(ctx, in)
	}
	if i.inner == nil {
		return &decompiler.Result{
			Name: i.Key(), Version: i.Pin.ID, Failed: true,
			FailReason: "no local runner configured",
		}, nil
	}
	res, err := i.inner.Decompile(ctx, in)
	if res != nil {
		res.Name = i.Key()
		res.Version = i.Pin.ID
	}
	return res, err
}

func (i *Instance) decompileDocker(ctx context.Context, input decompiler.Input) (*decompiler.Result, error) {
	res := &decompiler.Result{Name: i.Key(), Version: i.Pin.ID, OutDir: input.OutDir, JavaRoot: input.OutDir}
	docker, err := runner.LookPath("", "docker")
	if err != nil {
		res.Failed = true
		res.FailReason = "docker not available"
		return res, nil
	}
	absAPK, err := filepath.Abs(input.APKPath)
	if err != nil {
		res.Failed = true
		res.FailReason = err.Error()
		return res, nil
	}
	absOut, err := filepath.Abs(input.OutDir)
	if err != nil {
		res.Failed = true
		res.FailReason = err.Error()
		return res, nil
	}
	// Shared pattern: mount APK + out, run tool inside pinned image.
	args := []string{
		"run", "--rm",
		"-v", absAPK + ":/input/app.apk:ro",
		"-v", absOut + ":/output",
		i.image,
	}
	switch i.Tool {
	case "jadx":
		args = append(args, "jadx", "-d", "/output", "/input/app.apk")
	case "cfr":
		args = append(args, "java", "-jar", "/opt/cfr.jar", "/input/app.apk", "--outputdir", "/output")
	case "fernflower":
		args = append(args, "java", "-jar", "/opt/fernflower.jar", "/input/app.apk", "/output")
	default:
		res.Failed = true
		res.FailReason = "unsupported docker tool: " + i.Tool
		return res, nil
	}
	if _, err := runner.Run(ctx, docker, args...); err != nil {
		res.Failed = true
		res.FailReason = err.Error()
		res.Notes = append(res.Notes, "docker decompile failed — ensure image exists (see docker/)")
		return res, nil
	}
	src := ir.SourceJADX
	switch i.Tool {
	case "cfr":
		src = ir.SourceCFR
	case "fernflower":
		src = ir.SourceFernFlower
	}
	methods, err := javaast.ParseDir(input.OutDir, src)
	if err != nil {
		res.Notes = append(res.Notes, err.Error())
	}
	res.MethodIRs = methods
	return res, nil
}

// BuildInstances constructs runners from the version matrix.
func BuildInstances(cfg *registry.Config, paths decompiler.Paths, projectRoot string) ([]*Instance, []registry.ToolIdentity, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("nil version config")
	}
	var out []*Instance
	var ids []registry.ToolIdentity

	add := func(tool string, pin registry.PinnedVersion) error {
		ident := pin.Identity(tool, projectRoot)
		inst := &Instance{
			Tool:     tool,
			Pin:      pin,
			Identity: ident,
			javaPath: paths.Java,
		}
		switch strings.ToLower(pin.Runner) {
		case "docker":
			inst.docker = true
			inst.image = pin.DockerImage
			if inst.image == "" {
				return fmt.Errorf("%s@%s: docker runner requires docker_image", tool, pin.ID)
			}
		default:
			inner, err := buildLocal(tool, pin, paths, projectRoot)
			if err != nil {
				return err
			}
			inst.inner = inner
		}
		out = append(out, inst)
		ids = append(ids, ident)
		return nil
	}

	for _, tool := range []string{"jadx", "cfr", "fernflower"} {
		for _, pin := range cfg.EnabledVersions(tool) {
			if err := add(tool, pin); err != nil {
				return nil, nil, err
			}
		}
	}
	return out, ids, nil
}

func buildLocal(tool string, pin registry.PinnedVersion, paths decompiler.Paths, root string) (decompiler.Decompiler, error) {
	switch tool {
	case "jadx":
		p := paths.JADX
		if pin.Path != "" {
			p = resolve(root, pin.Path)
		} else if pin.Binary != "" {
			p = pin.Binary
		}
		return jadx.New(p), nil
	case "cfr":
		p := paths.CFR
		if pin.Path != "" {
			p = resolve(root, pin.Path)
		}
		return cfr.New(p, paths.Java), nil
	case "fernflower":
		p := paths.FernFlower
		if pin.Path != "" {
			p = resolve(root, pin.Path)
		} else if pin.Binary != "" {
			p = pin.Binary
		}
		return fernflower.New(p, paths.Java), nil
	default:
		return nil, fmt.Errorf("unknown tool %s", tool)
	}
}

func resolve(root, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, p)
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
