// Package cfg builds and compares control-flow graphs from MethodIR.
package cfg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/armin/apkcheck/internal/ir"
)

// Build constructs a CFG from a method's instructions and exception handlers.
// Labels referenced by branches become block boundaries.
func Build(method *ir.MethodIR) ir.CFG {
	if method == nil || len(method.Instructions) == 0 {
		return ir.CFG{}
	}

	leaders := map[int]bool{0: true}
	labelIndex := map[string]int{}

	for i, ins := range method.Instructions {
		if ins.Label != "" {
			labelIndex[ins.Label] = i
			leaders[i] = true
		}
	}

	for i, ins := range method.Instructions {
		if isBranch(ins.Opcode) || isSwitch(ins.Opcode) {
			if i+1 < len(method.Instructions) {
				leaders[i+1] = true
			}
			for _, t := range ins.Targets {
				if idx, ok := labelIndex[normalizeLabel(t)]; ok {
					leaders[idx] = true
				}
			}
		}
		if isTerminator(ins.Opcode) && i+1 < len(method.Instructions) {
			leaders[i+1] = true
		}
	}

	for _, h := range method.Exceptions {
		if idx, ok := labelIndex[normalizeLabel(h.Handler)]; ok {
			leaders[idx] = true
		}
		if idx, ok := labelIndex[normalizeLabel(h.StartLabel)]; ok {
			leaders[idx] = true
		}
	}

	starts := make([]int, 0, len(leaders))
	for i := range leaders {
		starts = append(starts, i)
	}
	sort.Ints(starts)

	blocks := make([]ir.BasicBlock, 0, len(starts))
	indexByStart := map[int]string{}
	for i, start := range starts {
		end := len(method.Instructions) - 1
		if i+1 < len(starts) {
			end = starts[i+1] - 1
		}
		id := fmt.Sprintf("B%d", i)
		indexByStart[start] = id
		blocks = append(blocks, ir.BasicBlock{
			ID:      id,
			Start:   start,
			End:     end,
			IsEntry: i == 0,
		})
	}

	labelToBlock := map[string]string{}
	for _, b := range blocks {
		for i := b.Start; i <= b.End; i++ {
			if lab := method.Instructions[i].Label; lab != "" {
				labelToBlock[lab] = b.ID
			}
		}
	}

	branchCount := 0
	edgeCount := 0
	exits := []string{}

	for bi := range blocks {
		b := &blocks[bi]
		last := method.Instructions[b.End]
		op := last.Opcode

		addEdge := func(to string) {
			if to == "" {
				return
			}
			for _, s := range b.Successors {
				if s == to {
					return
				}
			}
			b.Successors = append(b.Successors, to)
			edgeCount++
		}

		switch {
		case isReturn(op) || op == "throw" || op == "throw-verification-error":
			b.IsExit = true
			exits = append(exits, b.ID)
		case isGoto(op):
			if len(last.Targets) > 0 {
				addEdge(labelToBlock[normalizeLabel(last.Targets[0])])
			}
		case isBranch(op):
			branchCount++
			if len(last.Targets) > 0 {
				addEdge(labelToBlock[normalizeLabel(last.Targets[0])])
			}
			// fallthrough
			if b.End+1 < len(method.Instructions) {
				if nextID, ok := indexByStart[b.End+1]; ok {
					addEdge(nextID)
				}
			}
		case isSwitch(op):
			branchCount++
			for _, t := range last.Targets {
				addEdge(labelToBlock[normalizeLabel(t)])
			}
			if b.End+1 < len(method.Instructions) {
				if nextID, ok := indexByStart[b.End+1]; ok {
					addEdge(nextID)
				}
			}
		default:
			if b.End+1 < len(method.Instructions) {
				if nextID, ok := indexByStart[b.End+1]; ok {
					addEdge(nextID)
				}
			} else {
				b.IsExit = true
				exits = append(exits, b.ID)
			}
		}
	}

	// Fill predecessors.
	pred := map[string][]string{}
	for _, b := range blocks {
		for _, s := range b.Successors {
			pred[s] = append(pred[s], b.ID)
		}
	}
	for i := range blocks {
		blocks[i].Predecessors = pred[blocks[i].ID]
	}

	entry := ""
	if len(blocks) > 0 {
		entry = blocks[0].ID
	}

	cfg := ir.CFG{
		Entry:       entry,
		Exits:       exits,
		Blocks:      blocks,
		EdgeCount:   edgeCount,
		BranchCount: branchCount,
	}
	method.BasicBlocks = blocks
	method.ControlFlow = cfg
	return cfg
}

// StructuralCompare compares two CFGs at a structural level.
// It does not claim semantic equality of conditions.
type StructuralCompare struct {
	Compatible   bool
	BlockDelta   int
	BranchDelta  int
	EdgeDelta    int
	MissingExits bool
	Notes        []string
}

// CompareStructure reports coarse CFG compatibility between ground truth and reconstruction.
func CompareStructure(truth, other ir.CFG) StructuralCompare {
	res := StructuralCompare{Compatible: true}
	res.BlockDelta = abs(len(truth.Blocks) - len(other.Blocks))
	res.BranchDelta = abs(truth.BranchCount - other.BranchCount)
	res.EdgeDelta = abs(truth.EdgeCount - other.EdgeCount)

	// Allow small reconstruction variance: decompilers often merge/split blocks.
	if res.BlockDelta > max(2, len(truth.Blocks)/3) {
		res.Compatible = false
		res.Notes = append(res.Notes, fmt.Sprintf(
			"basic block count differs: truth=%d other=%d", len(truth.Blocks), len(other.Blocks)))
	}
	if res.BranchDelta > max(1, truth.BranchCount/2) {
		res.Compatible = false
		res.Notes = append(res.Notes, fmt.Sprintf(
			"branch count differs: truth=%d other=%d", truth.BranchCount, other.BranchCount))
	}
	if len(truth.Exits) > 0 && len(other.Exits) == 0 {
		res.Compatible = false
		res.MissingExits = true
		res.Notes = append(res.Notes, "reconstruction has no exit blocks while bytecode does")
	}
	if res.Compatible && (res.BlockDelta > 0 || res.BranchDelta > 0) {
		res.Notes = append(res.Notes, "minor structural variance within tolerance")
	}
	return res
}

func normalizeLabel(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ":")
	return s
}

func isBranch(op string) bool {
	return strings.HasPrefix(op, "if-") || op == "if" || op == "if_stmt"
}

func isGoto(op string) bool {
	return op == "goto" || op == "goto/16" || op == "goto/32" || op == "goto_stmt"
}

func isSwitch(op string) bool {
	return op == "packed-switch" || op == "sparse-switch" || op == "switch" || op == "switch_stmt"
}

func isReturn(op string) bool {
	return strings.HasPrefix(op, "return")
}

func isTerminator(op string) bool {
	return isReturn(op) || op == "throw" || op == "throw-verification-error" || isGoto(op)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
