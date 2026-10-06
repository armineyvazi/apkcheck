package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/armin/apkcheck/internal/lab/runtimes"
)

func labRuntime(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `apkcheck lab runtime — manage Android emulator/device instances

  list | status
  start  [--avd NAME] [--cold-boot] [--timeout 10m] [--workspace DIR]
  stop   [--serial SERIAL | --avd NAME | --all]
  restart [--avd NAME] [--cold-boot] [--timeout 10m] [--workspace DIR]

Note: --workspace is accepted for script consistency but unused (emulator ops are host-global).

Examples:
  apkcheck lab runtime list
  apkcheck lab runtime start --avd Pixel_8_API_34
  apkcheck lab runtime stop --avd Pixel_8_API_34
  apkcheck lab runtime stop --all
  apkcheck lab runtime restart --avd Pixel_8_API_34
`)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list", "status":
		return labRuntimeList(rest)
	case "start":
		return labRuntimeStart(rest)
	case "stop":
		return labRuntimeStop(rest)
	case "restart":
		return labRuntimeRestart(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown runtime subcommand: %s\n", sub)
		return 2
	}
}

func labRuntimeList(args []string) int {
	fs := flag.NewFlagSet("lab runtime list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.String("workspace", "", "accepted for CLI consistency (unused)")
	fs.SetOutput(os.Stderr)
	labBoolFlags["json"] = true
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	mgr := &runtimes.Manager{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := mgr.Snapshot(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *jsonOut {
		enc, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(enc))
		return 0
	}
	fmt.Printf("AVDs configured: %d · emulators running: %d · physical devices online: %d\n\n",
		st.AVDConfigured, st.EmulatorsRunning, st.DevicesOnline)
	fmt.Printf("%-10s %-22s %-16s %-10s %-8s %s\n", "KIND", "NAME", "SERIAL", "STATUS", "API", "NOTES")
	for _, inst := range st.Instances {
		name := inst.Name
		if name == "" {
			name = "—"
		}
		ser := inst.Serial
		if ser == "" {
			ser = "—"
		}
		api := inst.API
		if api == "" {
			api = "—"
		}
		note := inst.Connection
		if inst.Model != "" && inst.Kind == "device" {
			note = inst.Model
		}
		fmt.Printf("%-10s %-22s %-16s %-10s %-8s %s\n", inst.Kind, name, ser, inst.Status, api, note)
	}
	if len(st.Instances) == 0 {
		fmt.Println("(none — create an AVD: apkcheck emulator-create --name Pixel_8_API_34)")
	}
	return 0
}

func labRuntimeStart(args []string) int {
	fs := flag.NewFlagSet("lab runtime start", flag.ContinueOnError)
	avd := fs.String("avd", "Pixel_8_API_34", "AVD name")
	cold := fs.Bool("cold-boot", false, "cold boot (no snapshot)")
	timeout := fs.Duration("timeout", 10*time.Minute, "boot timeout")
	_ = fs.String("workspace", "", "accepted for CLI consistency (runtime is global; unused)")
	fs.SetOutput(os.Stderr)
	labBoolFlags["cold-boot"] = true
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	mgr := &runtimes.Manager{}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout+time.Minute)
	defer cancel()
	serial, err := mgr.Start(ctx, *avd, *cold, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("started %s → %s\n", *avd, serial)
	return 0
}

func labRuntimeStop(args []string) int {
	fs := flag.NewFlagSet("lab runtime stop", flag.ContinueOnError)
	avd := fs.String("avd", "", "AVD name")
	serial := fs.String("serial", "", "emulator serial (emulator-5554)")
	all := fs.Bool("all", false, "stop all running emulators")
	_ = fs.String("workspace", "", "accepted for CLI consistency (unused)")
	fs.SetOutput(os.Stderr)
	labBoolFlags["all"] = true
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	mgr := &runtimes.Manager{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if *all {
		stopped, err := mgr.StopAll(ctx)
		enc, _ := json.MarshalIndent(map[string]any{"stopped": stopped}, "", "  ")
		fmt.Println(string(enc))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if *serial == "" && *avd == "" {
		fmt.Fprintln(os.Stderr, "specify --serial, --avd, or --all")
		return 2
	}
	if err := mgr.Stop(ctx, *serial, *avd); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(`{"ok":true}`)
	return 0
}

func labRuntimeRestart(args []string) int {
	fs := flag.NewFlagSet("lab runtime restart", flag.ContinueOnError)
	avd := fs.String("avd", "Pixel_8_API_34", "AVD name")
	cold := fs.Bool("cold-boot", false, "cold boot")
	timeout := fs.Duration("timeout", 10*time.Minute, "boot timeout")
	_ = fs.String("workspace", "", "accepted for CLI consistency (unused)")
	fs.SetOutput(os.Stderr)
	labBoolFlags["cold-boot"] = true
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	mgr := &runtimes.Manager{}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout+time.Minute)
	defer cancel()
	serial, err := mgr.Restart(ctx, *avd, *cold, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("restarted %s → %s\n", *avd, serial)
	return 0
}
