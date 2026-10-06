// Package cache stores analysis artifacts keyed by APK content hash.
package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Store is a simple filesystem cache under a root directory.
type Store struct {
	Root string
}

// New creates a cache store.
func New(root string) *Store {
	return &Store{Root: root}
}

// Dir returns the cache directory for an APK hash.
func (s *Store) Dir(sha256 string) string {
	if len(sha256) < 4 {
		return filepath.Join(s.Root, sha256)
	}
	return filepath.Join(s.Root, sha256[:2], sha256)
}

// Ensure prepares the cache directory.
func (s *Store) Ensure(sha256 string) (string, error) {
	dir := s.Dir(sha256)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("mkdir cache: %w", err)
	}
	return dir, nil
}

// Meta is stored alongside cached artifacts.
type Meta struct {
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
	APKPath   string    `json:"apk_path"`
}

// WriteMeta writes cache metadata.
func (s *Store) WriteMeta(sha256 string, meta Meta) error {
	dir, err := s.Ensure(sha256)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o640)
}

// Has checks whether a named artifact subdirectory exists and is non-empty.
func (s *Store) Has(sha256, name string) bool {
	dir := filepath.Join(s.Dir(sha256), name)
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}
