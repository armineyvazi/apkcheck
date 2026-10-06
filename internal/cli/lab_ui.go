package cli

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab/api"
	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/certs"
	"github.com/armin/apkcheck/internal/lab/proxy"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/scenarios"
	"github.com/armin/apkcheck/internal/lab/security"
	"github.com/armin/apkcheck/internal/lab/session"
)

// labBoolFlags must not consume the following token as a value.
var labBoolFlags = map[string]bool{
	"open": true, "build": true, "dev": true,
	"h": true, "help": true,
}

func isLabBoolFlag(name string) bool {
	name = strings.TrimLeft(name, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	return labBoolFlags[name]
}

func listenURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// addr may be ":8787"
		if strings.HasPrefix(addr, ":") {
			return "http://127.0.0.1" + addr
		}
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// uiSearchRoots returns directories to probe for web/dist (cwd ancestors + binary location).
func uiSearchRoots() []string {
	var roots []string
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
		dir := cwd
		for i := 0; i < 6; i++ {
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			roots = append(roots, parent)
			dir = parent
		}
	}
	if exe, err := os.Executable(); err == nil {
		// Resolve symlinks (e.g. ~/.local/bin/apkcheck → …/apkcheck/bin/apkcheck).
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		binDir := filepath.Dir(exe)
		roots = append(roots, binDir)
		// bin/apkcheck → repo root
		roots = append(roots, filepath.Dir(binDir))
	}
	return roots
}

// locateWebDist finds web/dist/index.html under roots, also checking apkcheck/web/dist
// so `apkcheck lab ui` works from the parent sec/ directory.
func locateWebDist(roots ...string) string {
	seen := map[string]struct{}{}
	for _, root := range roots {
		for _, rel := range []string{
			filepath.Join("web", "dist"),
			filepath.Join("apkcheck", "web", "dist"),
		} {
			cand := filepath.Join(root, rel)
			if _, ok := seen[cand]; ok {
				continue
			}
			seen[cand] = struct{}{}
			if st, err := os.Stat(filepath.Join(cand, "index.html")); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(cand)
				return abs
			}
		}
	}
	return ""
}

// findWebDist locates a built React UI (web/dist), walking up from cwd and beside the binary.
func findWebDist() string {
	return locateWebDist(uiSearchRoots()...)
}

func locateWebRoot(roots ...string) string {
	if dist := locateWebDist(roots...); dist != "" {
		return filepath.Dir(dist) // …/web
	}
	seen := map[string]struct{}{}
	for _, root := range roots {
		for _, rel := range []string{
			filepath.Join("web", "package.json"),
			filepath.Join("apkcheck", "web", "package.json"),
		} {
			pkg := filepath.Join(root, rel)
			if _, ok := seen[pkg]; ok {
				continue
			}
			seen[pkg] = struct{}{}
			if st, err := os.Stat(pkg); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(filepath.Dir(pkg))
				return abs
			}
		}
	}
	return ""
}

func findWebRoot() string {
	return locateWebRoot(uiSearchRoots()...)
}

func ensureWebUIBuilt(force bool) (string, error) {
	if !force {
		if dist := findWebDist(); dist != "" {
			return dist, nil
		}
	}
	web := findWebRoot()
	if web == "" {
		return "", fmt.Errorf("web/ not found — run from the apkcheck repo, or pass --ui /path/to/web/dist")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		return "", fmt.Errorf("npm required to build UI (cd web && npm install && npm run build): %w", err)
	}
	fmt.Fprintln(os.Stderr, "building Lab UI (npm run build)…")
	install := exec.Command("npm", "install")
	install.Dir = web
	install.Stdout = os.Stderr
	install.Stderr = os.Stderr
	if err := install.Run(); err != nil {
		return "", fmt.Errorf("npm install: %w", err)
	}
	build := exec.Command("npm", "run", "build")
	build.Dir = web
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("npm run build: %w", err)
	}
	dist := filepath.Join(web, "dist")
	if st, err := os.Stat(filepath.Join(dist, "index.html")); err != nil || st.IsDir() {
		return "", fmt.Errorf("UI build missing index.html in %s", dist)
	}
	return dist, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func startLabHTTP(workspace, addr, uiDir string) (*http.Server, string, error) {
	store, pipe, bus, err := openLab(workspace)
	if err != nil {
		return nil, "", err
	}
	scen := &scenarios.Engine{Root: store.Root, Bus: bus}
	scen.EnsureBuiltins()
	secStore := &security.Store{Root: store.Root, Bus: bus}
	secEng := &security.Engine{Store: store, Sec: secStore, Bus: bus, Scenarios: scen}
	_ = security.SeedHarnessProject(store.Root, "testdata/lab/harness")
	sess := session.NewManager(store.Root, bus)
	recs := recording.NewManager(store.Root, bus, sess)
	apiSrv := &api.Server{
		Store: store, Pipe: pipe, Bus: bus,
		Proxy:      proxy.New(filepath.Join(store.Root, "proxy"), ":8080"),
		Scenarios:  scen,
		Certs:      &certs.Manager{Root: store.Root},
		Security:   secEng,
		Sessions:   sess,
		Recordings: recs,
		Auth:       authgate.New(store.Root, bus),
		UIDir:      uiDir,
	}
	url := listenURL(addr)
	hs := &http.Server{Addr: addr, Handler: apiSrv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	return hs, url, nil
}

func labServe(args []string) int {
	fs := flag.NewFlagSet("lab serve", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	addr := fs.String("addr", ":8787", "listen address")
	ui := fs.String("ui", "", "optional static UI directory (web/dist)")
	openFlag := fs.Bool("open", false, "open dashboard in browser")
	fs.SetOutput(os.Stderr)
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	uiDir := *ui
	if uiDir == "" {
		uiDir = findWebDist()
	}
	hs, url, err := startLabHTTP(*ws, *addr, uiDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "APKCheck Lab API  %s\n", url)
	fmt.Fprintf(os.Stderr, "workspace         %s\n", *ws)
	if uiDir != "" {
		fmt.Fprintf(os.Stderr, "UI                %s\n", uiDir)
	} else {
		fmt.Fprintln(os.Stderr, "UI                fallback HTML (run: apkcheck lab ui)")
	}
	if *openFlag {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func labUI(args []string) int {
	fs := flag.NewFlagSet("lab ui", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	addr := fs.String("addr", ":8787", "listen address")
	ui := fs.String("ui", "", "static UI directory (default: auto web/dist)")
	build := fs.Bool("build", false, "force npm build of web/")
	noOpen := fs.Bool("no-open", false, "do not open browser")
	dev := fs.Bool("dev", false, "also start Vite soft-reload on :5173")
	fs.SetOutput(os.Stderr)
	labBoolFlags["no-open"] = true
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}

	uiDir := *ui
	if uiDir == "" {
		var err error
		uiDir, err = ensureWebUIBuilt(*build)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else if st, err := os.Stat(filepath.Join(uiDir, "index.html")); err != nil || st.IsDir() {
		fmt.Fprintf(os.Stderr, "UI dir missing index.html: %s\n", uiDir)
		return 1
	}

	var vite *exec.Cmd
	if *dev {
		web := findWebRoot()
		if web == "" {
			fmt.Fprintln(os.Stderr, "--dev requires web/ with package.json")
			return 1
		}
		vite = exec.Command("npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173")
		vite.Dir = web
		vite.Stdout = os.Stderr
		vite.Stderr = os.Stderr
		if err := vite.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "vite: %v\n", err)
			return 1
		}
		defer func() {
			if vite.Process != nil {
				_ = vite.Process.Kill()
			}
		}()
		fmt.Fprintln(os.Stderr, "Vite dev UI      http://127.0.0.1:5173  (proxies /api → lab API)")
	}

	hs, url, err := startLabHTTP(*ws, *addr, uiDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "APKCheck Lab UI   %s\n", url)
	fmt.Fprintf(os.Stderr, "workspace         %s\n", *ws)
	fmt.Fprintf(os.Stderr, "UI assets         %s\n", uiDir)
	fmt.Fprintln(os.Stderr, "tip              Ctrl+C to stop · ⌘K command palette in the UI")

	openURL := url
	if *dev {
		openURL = "http://127.0.0.1:5173"
	}
	if !*noOpen {
		go func() {
			time.Sleep(400 * time.Millisecond)
			openBrowser(openURL)
		}()
	}
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
