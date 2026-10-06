package config_test

import (
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/runtime/config"
)

func TestLoadDurationsAndScenarios(t *testing.T) {
	cfg, err := config.Load("../../../configs/apkcheck.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Emulator.BootTimeout.Duration() != 360*time.Second {
		t.Fatalf("boot_timeout=%v", time.Duration(cfg.Emulator.BootTimeout))
	}
	if len(cfg.Scenarios) == 0 || !cfg.Scenarios[0].Actions[0].Launch {
		t.Fatalf("scenarios not parsed: %+v", cfg.Scenarios)
	}
	if cfg.Scenarios[0].Actions[1].Wait != 10*time.Second {
		t.Fatalf("wait=%v", cfg.Scenarios[0].Actions[1].Wait)
	}
	if cfg.Network.MITM {
		t.Fatal("mitm must stay false")
	}
}
