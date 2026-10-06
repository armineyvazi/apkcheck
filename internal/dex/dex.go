// Package dex provides lightweight DEX file inspection helpers.
//
// Full Dalvik bytecode decoding is intentionally deferred: Phase 1 uses
// Apktool Smali as the ground-truth IR. This package validates DEX magic
// and reports structural metadata.
package dex

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Info is basic DEX header metadata.
type Info struct {
	Path       string
	Magic      string
	Version    string
	FileSize   uint32
	HeaderSize uint32
	EndianTag  uint32
	ClassDefs  uint32
	MethodIDs  uint32
	StringIDs  uint32
}

// InspectHeader reads the DEX header without decoding bytecode.
func InspectHeader(path string) (*Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hdr [112]byte
	n, err := f.Read(hdr[:])
	if err != nil {
		return nil, fmt.Errorf("read dex header: %w", err)
	}
	if n < 112 {
		return nil, fmt.Errorf("dex header too short")
	}
	if string(hdr[0:4]) != "dex\n" {
		return nil, fmt.Errorf("invalid dex magic")
	}
	ver := string(hdr[4:7])
	endian := binary.LittleEndian.Uint32(hdr[40:44])
	if endian != 0x12345678 {
		return nil, fmt.Errorf("unsupported dex endian tag: 0x%x", endian)
	}
	return &Info{
		Path:       path,
		Magic:      "dex",
		Version:    ver,
		FileSize:   binary.LittleEndian.Uint32(hdr[32:36]),
		HeaderSize: binary.LittleEndian.Uint32(hdr[36:40]),
		EndianTag:  endian,
		StringIDs:  binary.LittleEndian.Uint32(hdr[56:60]),
		MethodIDs:  binary.LittleEndian.Uint32(hdr[80:84]),
		ClassDefs:  binary.LittleEndian.Uint32(hdr[96:100]),
	}, nil
}
