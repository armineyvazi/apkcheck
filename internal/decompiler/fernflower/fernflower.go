// Package fernflower integrates the FernFlower decompiler (optional).
package fernflower

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/parser/javaast"
	"github.com/armin/apkcheck/internal/runner"
)

// Decompiler runs FernFlower via brew wrapper or java -jar.
type Decompiler struct {
	JarPath  string // jar path or fernflower binary
	JavaPath string
}

func New(jar, java string) *Decompiler {
	return &Decompiler{JarPath: jar, JavaPath: java}
}

func (d *Decompiler) Name() string { return "fernflower" }

func (d *Decompiler) Available(ctx context.Context) bool {
	_, err := d.Version(ctx)
	return err == nil
}

func (d *Decompiler) Version(ctx context.Context) (string, error) {
	req, err := d.ResolveJava(ctx)
	if err != nil {
		// Still report jar presence when only Java is wrong.
		if _, jar, rerr := d.resolve(); rerr == nil && jar != "" {
			return "", fmt.Errorf("%w (jar: %s)", err, filepath.Base(jar))
		}
		return "", err
	}
	if req.JarPath != "" {
		return fmt.Sprintf("%s (Java %d+ via %s)", filepath.Base(req.JarPath), req.MinRelease, req.JavaPath), nil
	}
	exe, _, _ := d.resolve()
	return "available (" + exe + ")", nil
}

// resolve returns either (binary, "") or (java, jar).
// Prefer a jar + compatible JVM over the Homebrew launcher (which often picks an old JAVA_HOME).
func (d *Decompiler) resolve() (exe, jar string, err error) {
	if d.JarPath != "" {
		if strings.HasSuffix(strings.ToLower(d.JarPath), ".jar") {
			return d.JavaPath, d.JarPath, nil
		}
		p, lerr := runner.LookPath(d.JarPath, "fernflower")
		return p, "", lerr
	}

	if p := os.Getenv("FERNFLOWER_JAR"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return d.JavaPath, p, nil
		}
	}

	candidates := []string{
		"fernflower.jar",
		"intellij-fernflower.jar",
		"/usr/local/share/fernflower/fernflower.jar",
		"/opt/fernflower/fernflower.jar",
	}
	if matches, _ := filepath.Glob("/opt/homebrew/opt/fernflower/libexec/*.jar"); len(matches) > 0 {
		candidates = append(candidates, matches...)
	}
	if matches, _ := filepath.Glob("/usr/local/opt/fernflower/libexec/*.jar"); len(matches) > 0 {
		candidates = append(candidates, matches...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return d.JavaPath, c, nil
		}
	}

	if p, err := runner.LookPath("", "fernflower"); err == nil {
		return p, "", nil
	}
	return "", "", fmt.Errorf("fernflower not installed (brew install fernflower)")
}

func (d *Decompiler) Decompile(ctx context.Context, input decompiler.Input) (*decompiler.Result, error) {
	req, err := d.ResolveJava(ctx)
	if err != nil {
		return &decompiler.Result{Name: d.Name(), Failed: true, FailReason: err.Error()}, err
	}
	exe, jar, err := d.resolve()
	if err != nil {
		return &decompiler.Result{Name: d.Name(), Failed: true, FailReason: err.Error()}, err
	}
	out := filepath.Join(input.OutDir, "fernflower")
	if err := os.MkdirAll(out, 0o750); err != nil {
		return nil, err
	}
	ver, _ := d.Version(ctx)
	res := &decompiler.Result{Name: d.Name(), OutDir: out, JavaRoot: out, Version: ver}

	var runErr error
	if jar != "" {
		java := req.JavaPath
		if java == "" {
			java = exe
		}
		_, runErr = runner.Run(ctx, java, "-jar", jar, input.APKPath, out)
	} else {
		// Homebrew wrapper may itself pick a too-old JAVA_HOME; force a compatible one.
		envJava := req.JavaPath
		if envJava != "" {
			_, runErr = runner.RunEnv(ctx, []string{"JAVA_HOME=" + filepath.Dir(filepath.Dir(envJava)), "PATH=" + filepath.Dir(envJava) + ":" + os.Getenv("PATH")}, exe, input.APKPath, out)
		} else {
			_, runErr = runner.Run(ctx, exe, input.APKPath, out)
		}
	}
	if runErr != nil {
		res.Failed = true
		res.FailReason = runErr.Error()
		note := "fernflower decompilation failed (often requires DEX→JAR conversion first)"
		if req.MinRelease >= 21 {
			note = fmt.Sprintf("fernflower failed — needs Java %d+ (selected %s). Also may require DEX→JAR first", req.MinRelease, req.JavaVer)
		}
		res.Notes = append(res.Notes, note)
		return res, nil
	}

	methods, err := javaast.ParseDir(out, ir.SourceFernFlower)
	if err != nil {
		res.Notes = append(res.Notes, err.Error())
	}
	res.MethodIRs = methods
	if len(methods) == 0 {
		res.Notes = append(res.Notes, "no Java sources found; fernflower may have emitted jars only")
		res.Failed = true
		res.FailReason = "no java sources produced"
	}
	return res, nil
}
