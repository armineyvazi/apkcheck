// Package frida manages Frida dynamic instrumentation for Android targets.
//
// Frida (https://frida.re) enables runtime method hooking, SSL pinning bypass,
// and dynamic class-loading detection. This package:
//   - checks whether frida CLI tools are installed on the host
//   - pushes the correct frida-server binary to the device via ADB
//   - starts/stops frida-server on the device
//   - runs pre-built hook scripts (SSL unpin, method trace, DEX loader trace)
//
// # Authorization
//
// All operations target devices/apps the operator is explicitly authorized to test.
// frida-server requires root or debuggable app context on the device.
package frida

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
)

// ServerRemotePath is where frida-server is placed on the device.
const ServerRemotePath = "/data/local/tmp/frida-server"

// Hook is a named pre-built Frida JavaScript hook.
type Hook string

const (
	HookSSLUnpin    Hook = "ssl_unpin"    // bypass SSL certificate pinning
	HookMethodTrace Hook = "method_trace" // trace method calls matching a pattern
	HookDexLoader   Hook = "dex_loader"   // detect dynamic DEX class loading
	HookNetworkTrace Hook = "network_trace" // intercept Socket / URL connections
)

// Status describes Frida availability on host and device.
type Status struct {
	FridaCLI        string `json:"frida_cli"`           // path if found
	FridaVersion    string `json:"frida_version"`       // version string if found
	ServerOnDevice  bool   `json:"server_on_device"`    // frida-server present
	ServerRunning   bool   `json:"server_running"`      // frida-server process alive
	DeviceArch      string `json:"device_arch"`         // ro.product.cpu.abi
	Error           string `json:"error,omitempty"`
}

// TraceEvent is one captured runtime event from a Frida script.
type TraceEvent struct {
	At      time.Time         `json:"at"`
	Type    string            `json:"type"`
	Payload map[string]string `json:"payload,omitempty"`
}

// Manager handles Frida operations against a target device.
type Manager struct {
	Bus *events.Bus
}

func (m *Manager) emit(typ, msg, level string) {
	if m.Bus == nil {
		return
	}
	m.Bus.Publish(events.Event{Type: typ, Message: msg, Level: level})
}

// CheckHost returns the status of frida on the host machine.
func CheckHost() (path, version string, err error) {
	path, err = exec.LookPath("frida")
	if err != nil {
		return "", "", fmt.Errorf("frida not found — install with: pip install frida-tools")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return path, "", fmt.Errorf("frida --version: %w", err)
	}
	return path, strings.TrimSpace(string(out)), nil
}

// Status returns a combined host + device Frida status.
func (m *Manager) Status(ctx context.Context, serial string) *Status {
	st := &Status{}
	p, ver, err := CheckHost()
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.FridaCLI = p
	st.FridaVersion = ver

	if serial == "" {
		return st
	}
	st.DeviceArch = deviceArch(ctx, serial)

	// Check if frida-server binary is on device.
	if out := adbShellOutput(ctx, serial, "ls "+ServerRemotePath+" 2>/dev/null"); strings.Contains(out, "frida-server") {
		st.ServerOnDevice = true
	}
	// Check if frida-server process is running.
	if out := adbShellOutput(ctx, serial, "pgrep -l frida-server 2>/dev/null"); strings.Contains(out, "frida-server") {
		st.ServerRunning = true
	}
	return st
}

// PushServer pushes a frida-server binary from hostPath to the device.
// Download the correct binary from https://github.com/frida/frida/releases
// matching the device arch returned by Status().
func (m *Manager) PushServer(ctx context.Context, serial, hostPath string) error {
	if _, err := os.Stat(hostPath); err != nil {
		return fmt.Errorf("frida-server not found at %s: %w", hostPath, err)
	}
	m.emit("FRIDA_PUSH", "pushing frida-server to device "+serial, "info")
	if err := adbCmd(ctx, serial, "push", hostPath, ServerRemotePath); err != nil {
		return fmt.Errorf("adb push: %w", err)
	}
	if err := adbShell(ctx, serial, "chmod 755 "+ServerRemotePath); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	m.emit("FRIDA_PUSH", "frida-server pushed to "+ServerRemotePath, "info")
	return nil
}

// StartServer starts frida-server on the device in the background.
func (m *Manager) StartServer(ctx context.Context, serial string) error {
	// Kill any stale instance.
	_ = adbShell(ctx, serial, "pkill -f frida-server 2>/dev/null || true")
	time.Sleep(500 * time.Millisecond)
	m.emit("FRIDA_START", "starting frida-server on "+serial, "info")
	// Start frida-server in background on the device.
	// Use POSIX-compatible redirect (not bash's &>) — Android shell is mksh/ash.
	cmd := adbCmdArgs(ctx, serial, "shell", ServerRemotePath+" >/dev/null 2>&1 &")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start frida-server: %w", err)
	}
	// Wait in a goroutine so the adb shell process doesn't become a zombie.
	go func() { _ = cmd.Wait() }()
	time.Sleep(1500 * time.Millisecond) // give frida-server time to bind
	m.emit("FRIDA_START", "frida-server started", "info")
	return nil
}

// StopServer kills frida-server on the device.
func (m *Manager) StopServer(ctx context.Context, serial string) error {
	m.emit("FRIDA_STOP", "stopping frida-server on "+serial, "info")
	return adbShell(ctx, serial, "pkill -f frida-server 2>/dev/null || true")
}

// RunOptions configures a Frida hook run.
type RunOptions struct {
	Serial      string
	Package     string        // target package (spawn mode)
	Hook        Hook
	MethodPattern string     // for HookMethodTrace
	TimeoutSec  int
}

// RunHook executes a pre-built hook script against the target package.
// Events are streamed to the Bus and also returned as a slice.
func (m *Manager) RunHook(ctx context.Context, opts RunOptions) ([]TraceEvent, error) {
	fridaCLI, _, err := CheckHost()
	if err != nil {
		return nil, err
	}
	script, err := buildScript(opts.Hook, opts.MethodPattern)
	if err != nil {
		return nil, err
	}

	// Write script to a temp file; close handle before passing path to frida.
	tmp, err := os.CreateTemp("", "apkcheck-frida-*.js")
	if err != nil {
		return nil, fmt.Errorf("temp script: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, writeErr := tmp.WriteString(script)
	tmp.Close() // always close, even on write error
	if writeErr != nil {
		return nil, fmt.Errorf("write script: %w", writeErr)
	}

	to := opts.TimeoutSec
	if to <= 0 {
		to = 30
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(to)*time.Second)
	defer cancel()

	// Device selector: use -D <serial> if given, else -U (first USB/local device).
	// Never pass both — Frida treats them as conflicting device selectors.
	var args []string
	if opts.Serial != "" {
		args = append(args, "-D", opts.Serial)
	} else {
		args = append(args, "-U")
	}
	args = append(args,
		"-f", opts.Package,
		"--no-pause",
		"-l", tmpName,
	)
	m.emit("FRIDA_RUN", fmt.Sprintf("hook=%s pkg=%s", opts.Hook, opts.Package), "info")

	cmd := exec.CommandContext(runCtx, fridaCLI, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil && runCtx.Err() == nil {
		return nil, fmt.Errorf("frida: %w\n%s", err, out.String())
	}

	var traceEvents []TraceEvent
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		// Frida wraps send() calls as: {"type":"send","payload":<your object>}
		// Our scripts send: {type: 'X', payload: {key: value}}
		// So the outer payload contains {"type":"X","payload":{...}}.
		if idx := strings.Index(line, `{"type":"send"`); idx >= 0 {
			var outer struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			}
			if json.Unmarshal([]byte(line[idx:]), &outer) == nil && outer.Type == "send" {
				var inner struct {
					Type    string            `json:"type"`
					Payload map[string]string `json:"payload"`
				}
				if json.Unmarshal(outer.Payload, &inner) == nil && inner.Type != "" {
					ev := TraceEvent{At: time.Now(), Type: inner.Type, Payload: inner.Payload}
					traceEvents = append(traceEvents, ev)
					m.emit("FRIDA_EVENT", fmt.Sprintf("[%s] %v", inner.Type, inner.Payload), "info")
				}
			}
		} else if line != "" {
			m.emit("FRIDA_OUTPUT", line, "info")
		}
	}
	m.emit("FRIDA_RUN", fmt.Sprintf("hook=%s done — %d events", opts.Hook, len(traceEvents)), "info")
	return traceEvents, nil
}

// DownloadHint returns the GitHub release URL for the correct frida-server binary.
func DownloadHint(deviceArch string) string {
	// Map Android ABI → Frida release arch.
	arch := map[string]string{
		"arm64-v8a":   "android-arm64",
		"armeabi-v7a": "android-arm",
		"x86_64":      "android-x86_64",
		"x86":         "android-x86",
	}
	a, ok := arch[deviceArch]
	if !ok {
		a = "android-arm64"
	}
	return fmt.Sprintf("https://github.com/frida/frida/releases/latest/download/frida-server-%s.xz", a)
}

// HostArch returns the host arch string matching Frida release naming.
func HostArch() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return "macos-arm64"
	case "darwin/amd64":
		return "macos-x86_64"
	case "linux/amd64":
		return "linux-x86_64"
	case "linux/arm64":
		return "linux-arm64"
	default:
		return "linux-x86_64"
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func adbPath() string {
	p, _ := exec.LookPath("adb")
	return p
}

func adbCmd(ctx context.Context, serial string, args ...string) error {
	return adbCmdArgs(ctx, serial, args...).Run()
}

func adbCmdArgs(ctx context.Context, serial string, args ...string) *exec.Cmd {
	adb := adbPath()
	if adb == "" {
		adb = "adb"
	}
	base := []string{}
	if serial != "" {
		base = append(base, "-s", serial)
	}
	return exec.CommandContext(ctx, adb, append(base, args...)...)
}

func adbShell(ctx context.Context, serial, cmd string) error {
	return adbCmdArgs(ctx, serial, "shell", cmd).Run()
}

func adbShellOutput(ctx context.Context, serial, cmd string) string {
	out, _ := adbCmdArgs(ctx, serial, "shell", cmd).Output()
	return string(out)
}

func deviceArch(ctx context.Context, serial string) string {
	out := adbShellOutput(ctx, serial, "getprop ro.product.cpu.abi")
	return strings.TrimSpace(out)
}

// buildScript returns the JS source for the requested hook.
func buildScript(h Hook, pattern string) (string, error) {
	switch h {
	case HookSSLUnpin:
		return scriptSSLUnpin, nil
	case HookMethodTrace:
		if pattern == "" {
			pattern = "."
		}
		return strings.ReplaceAll(scriptMethodTrace, "{{PATTERN}}", pattern), nil
	case HookDexLoader:
		return scriptDexLoader, nil
	case HookNetworkTrace:
		return scriptNetworkTrace, nil
	default:
		return "", fmt.Errorf("unknown hook: %s", h)
	}
}

// ─── Embedded JS hook scripts ─────────────────────────────────────────────────

const scriptSSLUnpin = `
/* APKCheck Lab — Universal SSL Pinning Bypass
   Patches TrustManager, OkHttp3, Conscrypt, and HostnameVerifier.
   AUTHORIZED TESTING ONLY. */
Java.perform(function() {
  // 1. Build a trust-everything TrustManager
  var TrustAll = Java.registerClass({
    name: 'com.apkcheck.TrustAll',
    implements: [Java.use('javax.net.ssl.X509TrustManager')],
    methods: {
      checkClientTrusted: function(_chain, _authType) {},
      checkServerTrusted: function(_chain, _authType) {},
      getAcceptedIssuers: function() { return []; }
    }
  });
  var trustAllInst = TrustAll.$new();

  // 2. OkHttp3 builder
  try {
    var okb = Java.use('okhttp3.OkHttpClient$Builder');
    ['sslSocketFactory', 'hostnameVerifier'].forEach(function(m) {
      if (okb[m] && okb[m].overloads) {
        okb[m].overloads.forEach(function(ov) { try { ov.implementation = function() { return this; }; } catch(e) {} });
      }
    });
  } catch(e) {}

  // 3. Network security config — return permissive config for all hosts
  try {
    var nc = Java.use('android.security.net.config.NetworkSecurityConfig');
    nc.getConfigForHostname.implementation = function(_host) {
      return nc.getConfigForHostname.call(this, '');
    };
  } catch(e) {}

  // 4. Default HostnameVerifier
  try {
    var uc = Java.use('javax.net.ssl.HttpsURLConnection');
    uc.setDefaultHostnameVerifier.implementation = function(_v) {};
    uc.setSSLSocketFactory.implementation = function(_f) {};
  } catch(e) {}

  // 5. SSLContext.init with trustAllInst
  try {
    var ctx = Java.use('javax.net.ssl.SSLContext');
    ctx.init.implementation = function(km, _tm, sr) {
      var arr = Java.array('javax.net.ssl.TrustManager', [trustAllInst]);
      ctx.init.call(this, km, arr, sr);
    };
  } catch(e) {}

  send({type: 'SSL_UNPIN_ACTIVE', payload: {status: 'bypass installed'}});
  console.log('[APKCheck] SSL pinning bypass active — capture traffic via mitmproxy on :8080');
});
`

const scriptMethodTrace = `
/* APKCheck Lab — Method Trace
   Pattern: {{PATTERN}} */
Java.perform(function() {
  var pattern = '{{PATTERN}}';
  var count = 0;
  Java.enumerateLoadedClasses({
    onMatch: function(cls) {
      try {
        var c = Java.use(cls);
        var methods = c.class.getDeclaredMethods();
        methods.forEach(function(m) {
          var name = m.getName();
          if (pattern !== '.' && !name.toLowerCase().includes(pattern.toLowerCase())) return;
          try {
            c[name].overloads.forEach(function(ov) {
              ov.implementation = function() {
                var args = Array.prototype.slice.call(arguments).map(function(a) {
                  try { return String(a); } catch(e) { return '<unprintable>'; }
                });
                send({type: 'METHOD_TRACE', payload: {class: cls, method: name, args: args.join(', ')}});
                var ret = ov.apply(this, arguments);
                send({type: 'METHOD_RETURN', payload: {class: cls, method: name, ret: String(ret)}});
                return ret;
              };
              count++;
            });
          } catch(e) {}
        });
      } catch(e) {}
    },
    onComplete: function() {
      send({type: 'TRACE_READY', payload: {hooked_methods: String(count)}});
      console.log('[APKCheck] Method trace active — ' + count + ' methods hooked for pattern: {{PATTERN}}');
    }
  });
});
`

const scriptDexLoader = `
/* APKCheck Lab — Dynamic DEX / Class Loading Detector */
Java.perform(function() {
  // DexClassLoader
  try {
    var DexCL = Java.use('dalvik.system.DexClassLoader');
    DexCL.$init.overloads.forEach(function(ov) {
      ov.implementation = function(dexPath, optDir, libPath, parent) {
        send({type: 'DEX_LOAD', payload: {dex_path: String(dexPath), opt_dir: String(optDir)}});
        console.log('[APKCheck] DexClassLoader: ' + dexPath);
        return ov.call(this, dexPath, optDir, libPath, parent);
      };
    });
  } catch(e) {}

  // InMemoryDexClassLoader (API 26+)
  try {
    var IML = Java.use('dalvik.system.InMemoryDexClassLoader');
    IML.$init.overloads.forEach(function(ov) {
      ov.implementation = function() {
        send({type: 'IN_MEMORY_DEX', payload: {hint: 'in-memory DEX loading detected — likely obfuscation/packing'}});
        console.log('[APKCheck] InMemoryDexClassLoader invoked');
        return ov.apply(this, arguments);
      };
    });
  } catch(e) {}

  // PathClassLoader
  try {
    var PCL = Java.use('dalvik.system.PathClassLoader');
    PCL.$init.overloads.forEach(function(ov) {
      ov.implementation = function(path, parent) {
        send({type: 'PATH_CLASS_LOAD', payload: {path: String(path)}});
        return ov.call(this, path, parent);
      };
    });
  } catch(e) {}

  send({type: 'DEX_LOADER_WATCH_ACTIVE', payload: {status: 'monitoring class loaders'}});
  console.log('[APKCheck] DEX loader detector active');
});
`

const scriptNetworkTrace = `
/* APKCheck Lab — Network Connection Trace
   Intercepts Socket, URL, and OkHttp3 connections. */
Java.perform(function() {
  // java.net.URL.openConnection
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
      send({type: 'NET_CONNECT', payload: {url: this.toString(), method: 'openConnection'}});
      return this.openConnection.overload().call(this);
    };
  } catch(e) {}

  // java.net.Socket
  try {
    var Socket = Java.use('java.net.Socket');
    Socket.$init.overloads.forEach(function(ov) {
      ov.implementation = function() {
        var host = arguments[0] ? String(arguments[0]) : '';
        var port = arguments[1] ? String(arguments[1]) : '';
        send({type: 'SOCKET_CONNECT', payload: {host: host, port: port}});
        console.log('[APKCheck] Socket: ' + host + ':' + port);
        return ov.apply(this, arguments);
      };
    });
  } catch(e) {}

  // OkHttp3 RealCall
  try {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.execute.implementation = function() {
      var req = this.request.value;
      if (req) send({type: 'OKHTTP_REQUEST', payload: {url: req.url ? req.url.toString() : '', method: req.method ? req.method : ''}});
      return this.execute.call(this);
    };
  } catch(e) {}

  send({type: 'NET_TRACE_ACTIVE', payload: {status: 'monitoring network calls'}});
  console.log('[APKCheck] Network trace active');
});
`
