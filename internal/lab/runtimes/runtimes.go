// Package runtimes manages Android device/emulator instances for the Lab UI/CLI.
package runtimes

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/device"
	"github.com/armin/apkcheck/internal/runtime/emulator"
	"github.com/armin/apkcheck/internal/runtime/env"
)

// Instance is one runtime target (device or emulator).
type Instance struct {
	Kind       string `json:"kind"` // emulator | device
	Name       string `json:"name,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Status     string `json:"status"`
	API        string `json:"api,omitempty"`
	ABI        string `json:"abi,omitempty"`
	Model      string `json:"model,omitempty"`
	Connection string `json:"connection,omitempty"`
}

// Status is a compact overview for the dashboard.
type Status struct {
	AVDConfigured    int        `json:"avd_configured"`
	EmulatorsRunning int        `json:"emulators_running"`
	DevicesOnline    int        `json:"devices_online"`
	Instances        []Instance `json:"instances"`
	Note             string     `json:"note,omitempty"`
}

// Manager wraps SDK emulator + adb device listing.
type Manager struct {
	Bus *events.Bus
}

func (m *Manager) emit(typ, msg string) {
	if m.Bus == nil {
		return
	}
	m.Bus.Publish(events.Event{Type: typ, Message: msg, Level: "info"})
}

func (m *Manager) emu(ctx context.Context) (*emulator.Manager, error) {
	sdk, err := env.Bootstrap()
	if err != nil {
		sdk = env.Discover()
	}
	client, err := adb.New(sdk)
	if err != nil {
		return emulator.NewManager(sdk, nil), nil
	}
	return emulator.NewManager(sdk, client), nil
}

// Snapshot returns devices + AVDs for the UI.
func (m *Manager) Snapshot(ctx context.Context) (*Status, error) {
	st := &Status{Note: "Emulator runs on the Lab host (Linux + KVM). Set APKCHECK_ADB_HOST to reach a remote ADB server."}
	em, err := m.emu(ctx)
	if err != nil {
		return nil, err
	}
	avds, err := em.ListAVDs(ctx)
	if err != nil {
		st.Note = err.Error() + " · On laptop: scripts/setup-laptop-emulator.sh (needs /dev/kvm)"
	} else {
		st.AVDConfigured = len(avds)
		if len(avds) == 0 {
			st.Note = "No AVDs on this host — run scripts/setup-laptop-emulator.sh on the Lab laptop (KVM), then restart Lab container with ANDROID_HOME mounted"
		}
		for _, a := range avds {
			inst := Instance{
				Kind: "emulator", Name: a.Name, Serial: a.Serial,
				Status: a.Status, API: a.API, ABI: a.ABI, Connection: "emulator",
			}
			if a.Status == "running" {
				st.EmulatorsRunning++
			}
			st.Instances = append(st.Instances, inst)
		}
	}
	if em.ADB != nil {
		devs, err := device.List(ctx, em.ADB, true)
		if err == nil {
			mapped := map[string]struct{}{}
			for _, inst := range st.Instances {
				if inst.Serial != "" {
					mapped[inst.Serial] = struct{}{}
				}
			}
			for _, d := range devs {
				isEmu := d.IsEmulator || strings.HasPrefix(d.Serial, "emulator-")
				if isEmu {
					if _, ok := mapped[d.Serial]; ok {
						continue
					}
					st.EmulatorsRunning++
					st.Instances = append(st.Instances, Instance{
						Kind: "emulator", Name: "(unknown AVD)", Serial: d.Serial,
						Status: "running", Connection: "emulator", Model: d.Model,
					})
					mapped[d.Serial] = struct{}{}
					continue
				}
				if d.State == device.StateDevice {
					st.DevicesOnline++
				}
				st.Instances = append(st.Instances, Instance{
					Kind: "device", Name: d.Model, Serial: d.Serial, Status: d.State,
					API: d.APILevel, ABI: d.ABI, Model: d.Model, Connection: d.Connection,
				})
			}
		}
	}
	return st, nil
}

// Start boots an AVD (default Pixel_8_API_34).
func (m *Manager) Start(ctx context.Context, avd string, coldBoot bool, timeout time.Duration) (string, error) {
	if avd == "" {
		avd = "Pixel_8_API_34"
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	em, err := m.emu(ctx)
	if err != nil {
		return "", err
	}
	m.emit("RUNTIME_START_REQUESTED", avd)
	serial, err := em.Start(ctx, avd, coldBoot, timeout, os.Stderr)
	if err != nil {
		return "", err
	}
	m.emit("RUNTIME_STARTED", avd+" "+serial)
	return serial, nil
}

// Stop kills by serial and/or AVD name.
func (m *Manager) Stop(ctx context.Context, serial, avd string) error {
	em, err := m.emu(ctx)
	if err != nil {
		return err
	}
	switch {
	case serial != "":
		m.emit("RUNTIME_STOP_REQUESTED", serial)
		if err := em.Stop(ctx, serial); err != nil {
			return err
		}
		m.emit("RUNTIME_STOPPED", serial)
		return nil
	case avd != "":
		m.emit("RUNTIME_STOP_REQUESTED", avd)
		if err := em.StopAVD(ctx, avd); err != nil {
			return err
		}
		m.emit("RUNTIME_STOPPED", avd)
		return nil
	default:
		return fmt.Errorf("serial or avd required")
	}
}

// StopAll kills every running emulator.
func (m *Manager) StopAll(ctx context.Context) ([]string, error) {
	em, err := m.emu(ctx)
	if err != nil {
		return nil, err
	}
	m.emit("RUNTIME_STOP_ALL", "stopping all emulators")
	stopped, err := em.StopAll(ctx)
	m.emit("RUNTIME_STOPPED", fmt.Sprintf("%d instance(s)", len(stopped)))
	return stopped, err
}

// Restart stops then starts an AVD.
func (m *Manager) Restart(ctx context.Context, avd string, coldBoot bool, timeout time.Duration) (string, error) {
	if avd == "" {
		avd = "Pixel_8_API_34"
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	em, err := m.emu(ctx)
	if err != nil {
		return "", err
	}
	m.emit("RUNTIME_RESTART_REQUESTED", avd)
	var out io.Writer = os.Stderr
	serial, err := em.Restart(ctx, avd, coldBoot, timeout, out)
	if err != nil {
		return "", err
	}
	m.emit("RUNTIME_STARTED", avd+" "+serial)
	return serial, nil
}

// FreshAfterRecording stops every emulator instance, then cold-boots with wipe-data
// so the next scenario starts on a single clean guest (called after recording is finalized).
func (m *Manager) FreshAfterRecording(ctx context.Context, avd, serial string, timeout time.Duration) (string, error) {
	if avd == "" {
		avd = "Pixel_8_API_34"
	}
	if timeout <= 0 {
		timeout = 12 * time.Minute
	}
	m.emit("RUNTIME_FRESH_REQUESTED", avd+" after recording saved")
	// Prefer stop-all: host-started + container-started guests can both linger on one AVD.
	if _, err := m.StopAll(ctx); err != nil {
		_ = m.Stop(ctx, serial, avd)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		st, err := m.Snapshot(ctx)
		if err == nil && st != nil && st.EmulatorsRunning == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
	// Extra settle so qemu releases the AVD lock file.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(3 * time.Second):
	}
	return m.Start(ctx, avd, true, timeout)
}
