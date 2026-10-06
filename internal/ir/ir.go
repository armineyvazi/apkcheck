// Package ir defines the normalized intermediate representation used to
// compare Smali/DEX ground truth against decompiler reconstructions.
//
// Design principle: DEX/Smali is the source of truth. Decompiler output is
// evidence that may or may not be supported by the bytecode.
package ir

// Type represents a JVM/Dalvik type descriptor or human-readable name.
type Type string

// MethodIR is the normalized representation of a single method.
type MethodIR struct {
	ClassName     string
	MethodName    string
	Descriptor    string
	Parameters    []Type
	ReturnType    Type
	AccessFlags   []string
	Instructions  []Instruction
	BasicBlocks   []BasicBlock
	Calls         []Call
	FieldAccesses []FieldAccess
	Constants     []Constant
	Exceptions    []ExceptionHandler
	ControlFlow   CFG
	Source        SourceKind
	RawSource     string
	SourcePath    string
}

// SourceKind identifies where an IR was derived from.
type SourceKind string

const (
	SourceSmali      SourceKind = "smali"
	SourceJADX       SourceKind = "jadx"
	SourceCFR        SourceKind = "cfr"
	SourceFernFlower SourceKind = "fernflower"
)

// Instruction is a normalized bytecode or reconstructed statement.
type Instruction struct {
	Index    int
	Opcode   string
	Operands []string
	Label    string
	Targets  []string // branch/switch targets
	Comment  string
}

// BasicBlock is a straight-line sequence ending at a branch, return, or throw.
type BasicBlock struct {
	ID           string
	Start        int
	End          int // inclusive instruction index
	Successors   []string
	Predecessors []string
	IsEntry      bool
	IsExit       bool
	IsException  bool
}

// Call is a method invocation site.
type Call struct {
	InvokeKind string // invoke-virtual, invoke-static, method call, etc.
	Owner      string
	Name       string
	Descriptor string
}

// Key returns a stable identity for call-set comparison.
func (c Call) Key() string {
	if c.Descriptor != "" {
		return c.Owner + "->" + c.Name + c.Descriptor
	}
	return c.Owner + "->" + c.Name
}

// FieldAccess is a field read or write.
type FieldAccess struct {
	Kind  string // get / put
	Owner string
	Name  string
	Type  string
}

// Key returns a stable identity for field-set comparison.
func (f FieldAccess) Key() string {
	return f.Kind + ":" + f.Owner + "->" + f.Name + ":" + f.Type
}

// Constant is a literal used by the method.
type Constant struct {
	Kind  string // string, int, long, float, double, class, null
	Value string
}

// ExceptionHandler describes a try/catch region.
type ExceptionHandler struct {
	StartLabel string
	EndLabel   string
	Handler    string
	Type       string // exception class or "any"
}

// CFG is the control-flow graph for a method.
type CFG struct {
	Entry       string
	Exits       []string
	Blocks      []BasicBlock
	EdgeCount   int
	BranchCount int
}

// Summary returns aggregate counts used for quick comparison.
func (m *MethodIR) Summary() Summary {
	returns, throws, monitors, creates := 0, 0, 0, 0
	for _, ins := range m.Instructions {
		switch {
		case isReturn(ins.Opcode):
			returns++
		case ins.Opcode == "throw" || ins.Opcode == "throw-verification-error":
			throws++
		case ins.Opcode == "monitor-enter" || ins.Opcode == "monitor-exit" ||
			ins.Opcode == "synchronized" || ins.Opcode == "synchronized_end":
			monitors++
		case ins.Opcode == "new-instance" || ins.Opcode == "new" || ins.Opcode == "new-array":
			creates++
		}
	}
	return Summary{
		Instructions:  len(m.Instructions),
		BasicBlocks:   len(m.BasicBlocks),
		Branches:      m.ControlFlow.BranchCount,
		Calls:         len(m.Calls),
		FieldAccesses: len(m.FieldAccesses),
		Returns:       returns,
		Throws:        throws,
		Exceptions:    len(m.Exceptions),
		Monitors:      monitors,
		ObjectCreates: creates,
		Constants:     len(m.Constants),
	}
}

func isReturn(op string) bool {
	switch op {
	case "return", "return-void", "return-object", "return-wide",
		"return-stmt", "return_stmt":
		return true
	default:
		return false
	}
}

// Summary holds countable method features for comparison.
type Summary struct {
	Instructions  int
	BasicBlocks   int
	Branches      int
	Calls         int
	FieldAccesses int
	Returns       int
	Throws        int
	Exceptions    int
	Monitors      int
	ObjectCreates int
	Constants     int
}

// Ref returns a stable method identity string.
func (m *MethodIR) Ref() string {
	return m.ClassName + "->" + m.MethodName + m.Descriptor
}
