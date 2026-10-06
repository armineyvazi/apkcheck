package registry_test

import (
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/registry"
)

func TestLoadVersionsYAML(t *testing.T) {
	root := filepath.Join("..", "..")
	path := filepath.Join(root, "configs", "versions.yaml")
	cfg, err := registry.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.EnabledVersions("cfr")) == 0 {
		t.Fatal("expected enabled cfr pin")
	}
	pin := cfg.EnabledVersions("cfr")[0]
	id := pin.Identity("cfr", root)
	if !id.Verified {
		t.Fatalf("cfr pin should verify: %+v", id)
	}
}
