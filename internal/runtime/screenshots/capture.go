// Package screenshots captures optional device screenshots via adb.
package screenshots

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Capture saves a PNG screenshot using device-side screencap + adb pull
// (avoids binary corruption through text stdout pipes).
func Capture(ctx context.Context, client *adb.Client, serial, dir, name string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	remote := "/data/local/tmp/apkcheck-shot.png"
	if _, err := client.Shell(ctx, serial, "screencap", "-p", remote); err != nil {
		// fallback to sdcard
		remote = "/sdcard/apkcheck-shot.png"
		if _, err2 := client.Shell(ctx, serial, "screencap", "-p", remote); err2 != nil {
			return "", fmt.Errorf("screencap: %w", err)
		}
	}
	if _, err := client.SerialRun(ctx, serial, "pull", remote, path); err != nil {
		return "", fmt.Errorf("adb pull screenshot: %w", err)
	}
	_, _ = client.Shell(ctx, serial, "rm", "-f", remote)
	return path, nil
}
