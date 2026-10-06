// Package pipeline implements decompile → rebuild → sign → validate for APK Lab.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/internal/decompiler/apktool"
	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/runner"
	appruntime "github.com/armin/apkcheck/internal/runtime"
	"github.com/armin/apkcheck/internal/runtime/env"
)

// Tools holds optional absolute paths; empty = discover.
type Tools struct {
	Apktool   string
	Apksigner string
	Zipalign  string
	Keytool   string
	Jarsigner string
}

// Pipeline orchestrates rebuild lifecycle.
type Pipeline struct {
	Store *lab.Store
	Bus   *events.Bus
	Tools Tools
}

func (p *Pipeline) emit(typ, artifactID, msg, level string) {
	if p.Bus == nil {
		return
	}
	p.Bus.Publish(events.Event{Type: typ, ArtifactID: artifactID, Message: msg, Level: level})
}

// ImportAPK copies/registers an original APK.
func (p *Pipeline) ImportAPK(src, label string) (*lab.Artifact, error) {
	info, err := apk.Inspect(src)
	if err != nil {
		return nil, err
	}
	if info.Package == "" {
		if pkg := packageViaAAPT(src); pkg != "" {
			info.Package = pkg
		}
	}
	id := lab.NewID("apk")
	dest := filepath.Join(p.Store.Root, "apks", id+".apk")
	if err := copyFile(src, dest); err != nil {
		return nil, err
	}
	if label == "" {
		label = filepath.Base(src)
	}
	a := &lab.Artifact{
		ID: id, Kind: lab.KindOriginalAPK, Path: dest,
		Package: info.Package, Label: label, SHA256: info.SHA256,
		Meta: map[string]string{"source": src},
	}
	if err := p.Store.Put(a); err != nil {
		return nil, err
	}
	p.emit("APK_IMPORTED", id, label, "info")
	return a, nil
}

func packageViaAAPT(apkPath string) string {
	aapt := findBuildTool("aapt")
	if aapt == "" {
		if p, err := exec.LookPath("aapt"); err == nil {
			aapt = p
		}
	}
	if aapt == "" {
		return ""
	}
	out, err := exec.Command(aapt, "dump", "badging", apkPath).CombinedOutput()
	if err != nil {
		return ""
	}
	// package: name='com.example'
	const pref = "package: name='"
	s := string(out)
	i := strings.Index(s, pref)
	if i < 0 {
		return ""
	}
	s = s[i+len(pref):]
	j := strings.IndexByte(s, '\'')
	if j < 0 {
		return ""
	}
	return s[:j]
}

// Decompile runs apktool d into a tracked project.
func (p *Pipeline) Decompile(ctx context.Context, apkID string) (*lab.Artifact, error) {
	parent, err := p.Store.Get(apkID)
	if err != nil {
		return nil, err
	}
	p.emit("DECOMPILE_STARTED", apkID, parent.Path, "info")
	id := lab.NewID("proj")
	outRoot := filepath.Join(p.Store.Root, "projects", id)
	_ = os.MkdirAll(outRoot, 0o750)

	at := apktool.New(p.Tools.Apktool)
	dec, err := at.Decode(ctx, parent.Path, outRoot)
	if err != nil {
		p.emit("DECOMPILE_FAILED", apkID, err.Error(), "error")
		return nil, err
	}
	a := &lab.Artifact{
		ID: id, Kind: lab.KindProject, Path: dec.OutDir, ParentID: apkID,
		Package: parent.Package, Label: parent.Label + " (project)",
		Meta: map[string]string{
			"apktool_version": dec.Version,
			"methods":         fmt.Sprintf("%d", len(dec.Methods)),
		},
	}
	if err := p.Store.Put(a); err != nil {
		return nil, err
	}
	p.emit("DECOMPILE_COMPLETED", id, dec.OutDir, "info")
	return a, nil
}

// Build runs apktool b on a project → unsigned APK.
func (p *Pipeline) Build(ctx context.Context, projectID string) (*lab.Artifact, error) {
	proj, err := p.Store.Get(projectID)
	if err != nil {
		return nil, err
	}
	if proj.Kind != lab.KindProject {
		return nil, fmt.Errorf("artifact %s is not a project", projectID)
	}
	p.emit("BUILD_STARTED", projectID, proj.Path, "info")
	path, err := runner.LookPath(p.Tools.Apktool, "apktool")
	if err != nil {
		return nil, err
	}
	id := lab.NewID("build")
	dest := filepath.Join(p.Store.Root, "builds", id+"-unsigned.apk")
	_ = os.MkdirAll(filepath.Dir(dest), 0o750)
	logPath := filepath.Join(p.Store.Root, "logs", id+"-build.log")

	res, err := runner.Run(ctx, path, "b", "-f", "-o", dest, proj.Path)
	out := ""
	if res != nil {
		out = res.Stdout + "\n" + res.Stderr
	}
	_ = os.WriteFile(logPath, []byte(out), 0o640)
	if err != nil {
		p.emit("BUILD_FAILED", projectID, err.Error(), "error")
		return nil, fmt.Errorf("apktool build: %w\nlog: %s", err, logPath)
	}
	sum, _ := fileSHA(dest)
	a := &lab.Artifact{
		ID: id, Kind: lab.KindUnsignedAPK, Path: dest, ParentID: projectID,
		Package: proj.Package, Label: proj.Label + " (unsigned)", SHA256: sum,
		Meta: map[string]string{"build_log": logPath},
	}
	if err := p.Store.Put(a); err != nil {
		return nil, err
	}
	p.emit("BUILD_COMPLETED", id, dest, "info")
	return a, nil
}

// Sign aligns + signs an APK with a debug keystore (lab cert).
func (p *Pipeline) Sign(ctx context.Context, unsignedID string) (*lab.Artifact, error) {
	u, err := p.Store.Get(unsignedID)
	if err != nil {
		return nil, err
	}
	switch u.Kind {
	case lab.KindUnsignedAPK, lab.KindOriginalAPK:
	default:
		return nil, fmt.Errorf("sign expects unsigned/original apk, got %s", u.Kind)
	}
	p.emit("SIGN_STARTED", unsignedID, u.Path, "info")

	keystore, err := p.ensureDebugKeystore()
	if err != nil {
		return nil, err
	}
	id := lab.NewID("signed")
	aligned := filepath.Join(p.Store.Root, "builds", id+"-aligned.apk")
	signed := filepath.Join(p.Store.Root, "builds", id+"-signed.apk")
	logPath := filepath.Join(p.Store.Root, "logs", id+"-sign.log")
	var logb strings.Builder

	inAPK := u.Path
	if zipalign := p.resolveZipalign(); zipalign != "" {
		cmd := exec.CommandContext(ctx, zipalign, "-f", "4", inAPK, aligned)
		out, err := cmd.CombinedOutput()
		logb.Write(out)
		if err != nil {
			_ = os.WriteFile(logPath, []byte(logb.String()), 0o640)
			p.emit("SIGN_FAILED", unsignedID, err.Error(), "error")
			return nil, fmt.Errorf("zipalign: %w", err)
		}
		inAPK = aligned
	} else {
		logb.WriteString("zipalign not found — skipping align\n")
		if err := copyFile(u.Path, aligned); err != nil {
			return nil, err
		}
		inAPK = aligned
	}

	if apksigner := p.resolveApksigner(); apksigner != "" {
		cmd := exec.CommandContext(ctx, apksigner, "sign",
			"--ks", keystore,
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--out", signed,
			inAPK,
		)
		out, err := cmd.CombinedOutput()
		logb.Write(out)
		if err != nil {
			_ = os.WriteFile(logPath, []byte(logb.String()), 0o640)
			p.emit("SIGN_FAILED", unsignedID, err.Error(), "error")
			return nil, fmt.Errorf("apksigner: %w\n%s", err, string(out))
		}
	} else {
		jarsigner, err := runner.LookPath(p.Tools.Jarsigner, "jarsigner")
		if err != nil {
			return nil, fmt.Errorf("neither apksigner nor jarsigner available")
		}
		if err := copyFile(inAPK, signed); err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, jarsigner,
			"-keystore", keystore,
			"-storepass", "android",
			"-keypass", "android",
			signed, "apkcheck",
		)
		out, err := cmd.CombinedOutput()
		logb.Write(out)
		if err != nil {
			_ = os.WriteFile(logPath, []byte(logb.String()), 0o640)
			p.emit("SIGN_FAILED", unsignedID, err.Error(), "error")
			return nil, fmt.Errorf("jarsigner: %w", err)
		}
		logb.WriteString("NOTE: jarsigner produces v1 signature only\n")
	}
	_ = os.WriteFile(logPath, []byte(logb.String()), 0o640)
	sum, _ := fileSHA(signed)
	a := &lab.Artifact{
		ID: id, Kind: lab.KindSignedAPK, Path: signed, ParentID: unsignedID,
		Package: u.Package, Label: stripSuffix(u.Label) + " (signed)", SHA256: sum,
		Meta: map[string]string{"sign_log": logPath, "keystore": keystore, "cert": "apkcheck-debug"},
	}
	if err := p.Store.Put(a); err != nil {
		return nil, err
	}
	p.emit("SIGN_COMPLETED", id, signed, "info")
	return a, nil
}

// RebuildFull is decode→build→sign from an original APK id.
func (p *Pipeline) RebuildFull(ctx context.Context, apkID string) (*lab.Artifact, error) {
	proj, err := p.Decompile(ctx, apkID)
	if err != nil {
		return nil, err
	}
	unsigned, err := p.Build(ctx, proj.ID)
	if err != nil {
		return nil, err
	}
	return p.Sign(ctx, unsigned.ID)
}

// ValidateOptions controls install/launch smoke test.
type ValidateOptions struct {
	EmulatorAVD  string
	DeviceSerial string
	Duration     time.Duration
	OutputDir    string
}

// Validate installs and launches a signed APK, checking stages.
func (p *Pipeline) Validate(ctx context.Context, signedID string, opt ValidateOptions) (*lab.ValidateResult, error) {
	art, err := p.Store.Get(signedID)
	if err != nil {
		return nil, err
	}
	if art.Kind != lab.KindSignedAPK && art.Kind != lab.KindOriginalAPK {
		return nil, fmt.Errorf("validate expects signed or original apk, got %s", art.Kind)
	}
	res := &lab.ValidateResult{
		ArtifactID: signedID,
		StartedAt:  time.Now().UTC(),
	}
	add := func(name string, ok bool, detail, errMsg string) {
		res.Stages = append(res.Stages, lab.ValidateStage{Name: name, OK: ok, Detail: detail, Error: errMsg})
		level := "info"
		if !ok {
			level = "error"
		}
		p.emit("VALIDATE_"+strings.ToUpper(name), signedID, detail+errMsg, level)
	}

	if art.Kind == lab.KindSignedAPK {
		add("build", true, "signed artifact present", "")
		add("sign", true, art.Meta["cert"], "")
	} else {
		add("build", true, "original apk (no rebuild)", "")
		add("sign", true, "original signature", "")
	}
	if _, err := os.Stat(art.Path); err != nil {
		add("build", false, "", err.Error())
		res.EndedAt = time.Now().UTC()
		_ = writeValidateJSON(opt.OutputDir, res)
		return res, err
	}

	outDir := opt.OutputDir
	if outDir == "" {
		outDir = filepath.Join(p.Store.Root, "runs", lab.NewID("run"))
	}
	_ = os.MkdirAll(outDir, 0o750)

	mode := "emulator"
	if opt.DeviceSerial != "" {
		mode = "device"
	}
	if opt.EmulatorAVD == "" && mode == "emulator" {
		opt.EmulatorAVD = "Pixel_8_API_34"
	}
	if opt.Duration <= 0 {
		opt.Duration = 15 * time.Second
	}

	p.emit("INSTALL_STARTED", signedID, art.Path, "info")
	ev, rerr := appruntime.Run(ctx, appruntime.Options{
		APKPath:      art.Path,
		OutputDir:    outDir,
		Mode:         mode,
		DeviceSerial: opt.DeviceSerial,
		EmulatorAVD:  opt.EmulatorAVD,
		Duration:     opt.Duration,
		KeepEmulator: true,
		BootTimeout:  10 * time.Minute,
	})
	if ev != nil {
		res.SessionID = ev.SessionID
	}

	installOK := rerr == nil && ev != nil && ev.Install != nil && ev.Install.Success
	if !installOK {
		msg := "install failed"
		if rerr != nil {
			msg = rerr.Error()
		} else if ev != nil && ev.Install != nil && ev.Install.Error != "" {
			msg = ev.Install.Error
		}
		add("install", false, "", msg)
		res.OK = false
		res.EndedAt = time.Now().UTC()
		_ = writeValidateJSON(outDir, res)
		return res, fmt.Errorf("validate install: %s", msg)
	}
	add("install", true, "adb install ok", "")
	p.emit("INSTALL_COMPLETED", signedID, "ok", "info")

	launchOK := ev.Launch != nil && ev.Launch.Success
	if launchOK {
		add("launch", true, ev.Launch.Target.Activity, "")
	} else {
		msg := "launch did not start"
		if ev.Launch != nil && ev.Launch.Error != "" {
			msg = ev.Launch.Error
		}
		add("launch", false, "", msg)
	}

	startupOK := ev.Process != nil && ev.Process.PID != ""
	if startupOK {
		add("startup", true, "pid="+ev.Process.PID, "")
	} else {
		add("startup", false, "", "process not running after launch")
	}

	crashOK := len(ev.Crashes) == 0
	if crashOK {
		add("crash_detection", true, "no crashes observed in window", "")
	} else {
		add("crash_detection", false, "", fmt.Sprintf("%d crash(es)", len(ev.Crashes)))
	}

	smokeOK := launchOK && startupOK && crashOK
	add("smoke", smokeOK, "launch+process+no crash", "")
	if len(ev.Network) > 0 {
		add("network", true, fmt.Sprintf("%d observations", len(ev.Network)), "")
	} else {
		add("network", true, "no network hints (NOT OBSERVED ≠ absent)", "")
	}

	res.OK = smokeOK && installOK
	res.EndedAt = time.Now().UTC()
	_ = writeValidateJSON(outDir, res)
	level := "info"
	if !res.OK {
		level = "error"
	}
	p.emit("VALIDATE_COMPLETED", signedID, fmt.Sprintf("ok=%v", res.OK), level)
	return res, nil
}

func writeValidateJSON(dir string, res *lab.ValidateResult) error {
	if dir == "" {
		return nil
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "validate.json"), data, 0o640)
}

func (p *Pipeline) ensureDebugKeystore() (string, error) {
	ks := filepath.Join(p.Store.Root, "certs", "apkcheck-debug.keystore")
	if st, err := os.Stat(ks); err == nil && st.Size() > 0 {
		return ks, nil
	}
	_ = os.MkdirAll(filepath.Dir(ks), 0o750)
	keytool, err := runner.LookPath(p.Tools.Keytool, "keytool")
	if err != nil {
		return "", fmt.Errorf("keytool required to create debug keystore: %w", err)
	}
	cmd := exec.Command(keytool,
		"-genkeypair", "-v",
		"-keystore", ks,
		"-alias", "apkcheck",
		"-keyalg", "RSA", "-keysize", "2048",
		"-validity", "10000",
		"-storepass", "android",
		"-keypass", "android",
		"-dname", "CN=apkcheck-lab,OU=lab,O=apkcheck,L=local,S=local,C=US",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("keytool: %w\n%s", err, out)
	}
	return ks, nil
}

func (p *Pipeline) resolveApksigner() string {
	if p.Tools.Apksigner != "" {
		return p.Tools.Apksigner
	}
	if s := findBuildTool("apksigner"); s != "" {
		return s
	}
	if pth, err := exec.LookPath("apksigner"); err == nil {
		return pth
	}
	return ""
}

func (p *Pipeline) resolveZipalign() string {
	if p.Tools.Zipalign != "" {
		return p.Tools.Zipalign
	}
	if s := findBuildTool("zipalign"); s != "" {
		return s
	}
	if pth, err := exec.LookPath("zipalign"); err == nil {
		return pth
	}
	return ""
}

func findBuildTool(name string) string {
	sdk, _ := env.Bootstrap()
	root := sdk.Root
	if root == "" {
		root = os.Getenv("ANDROID_HOME")
	}
	if root == "" {
		return ""
	}
	bt := filepath.Join(root, "build-tools")
	entries, err := os.ReadDir(bt)
	if err != nil {
		return ""
	}
	var best string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cand := filepath.Join(bt, e.Name(), name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			best = cand
		}
	}
	return best
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o640)
}

func fileSHA(path string) (string, error) {
	info, err := apk.Inspect(path)
	if err != nil {
		return "", err
	}
	return info.SHA256, nil
}

func stripSuffix(s string) string {
	for _, suf := range []string{" (unsigned)", " (signed)", " (project)"} {
		s = strings.TrimSuffix(s, suf)
	}
	return s
}
