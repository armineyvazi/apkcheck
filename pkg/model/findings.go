package model

// EvidenceClass is the epistemic label for a claim.
// Never present INFERENCE as a confirmed fact.
type EvidenceClass string

const (
	EvidenceStatic      EvidenceClass = "STATIC_EVIDENCE"
	EvidenceRuntime     EvidenceClass = "RUNTIME_OBSERVATION"
	EvidenceInference   EvidenceClass = "INFERENCE"
	EvidenceFact        EvidenceClass = "FACT"
	EvidenceObservation EvidenceClass = "OBSERVATION"
	EvidenceUncertainty EvidenceClass = "UNCERTAINTY"
)

// SemanticConfidence rates behavioral equivalence vs Smali/DEX (not mere parse success).
type SemanticConfidence string

const (
	SemanticHigh      SemanticConfidence = "HIGH"
	SemanticMedium    SemanticConfidence = "MEDIUM"
	SemanticLow       SemanticConfidence = "LOW"
	SemanticUncertain SemanticConfidence = "UNCERTAIN"
)

// FindingCategory groups actionable security findings.
type FindingCategory string

const (
	CatExportedComponent  FindingCategory = "exported_component"
	CatDangerousPerm      FindingCategory = "dangerous_permission"
	CatCleartext          FindingCategory = "cleartext_traffic"
	CatNetworkConfig      FindingCategory = "network_config"
	CatDebuggable         FindingCategory = "debuggable"
	CatBackup             FindingCategory = "backup"
	CatWebView            FindingCategory = "webview"
	CatDangerousAPI       FindingCategory = "dangerous_api"
	CatWeakCrypto         FindingCategory = "weak_crypto"
	CatHardcodedSecret    FindingCategory = "hardcoded_secret"
	CatInsecureStorage    FindingCategory = "insecure_storage"
	CatAuthz              FindingCategory = "auth_authz"
	CatSuspiciousPath     FindingCategory = "suspicious_path"
	CatNativeJNI          FindingCategory = "native_jni"
	CatDecompilerDisagree FindingCategory = "decompiler_disagreement"
)

// EvidenceLink points into the evidence graph / artifacts.
type EvidenceLink struct {
	APK        string `json:"apk,omitempty"`
	Split      string `json:"split,omitempty"`
	DEX        string `json:"dex,omitempty"`
	Class      string `json:"class,omitempty"`
	Method     string `json:"method,omitempty"`
	Descriptor string `json:"descriptor,omitempty"`
	SmaliFile  string `json:"smali_file,omitempty"`
	SmaliInsn  string `json:"smali_instruction,omitempty"`
	Manifest   string `json:"manifest_entry,omitempty"`
	Resource   string `json:"resource,omitempty"`
	NativeLib  string `json:"native_lib,omitempty"`
	SourcePath string `json:"source_path,omitempty"` // decompiled representation path
	NodeID     string `json:"node_id,omitempty"`     // evidence graph node
}

// Finding is an actionable security triage item with explicit evidence discipline.
type Finding struct {
	ID          string          `json:"id"`
	Category    FindingCategory `json:"category"`
	Title       string          `json:"title"`
	Severity    Severity        `json:"severity"`
	Class       EvidenceClass   `json:"evidence_class"`
	Confidence  Confidence      `json:"confidence"` // CONSISTENT-style epistemic confidence of the *finding*
	Summary     string          `json:"summary"`
	Why         string          `json:"why"` // why APKCheck reported this
	Evidence    []EvidenceLink  `json:"evidence,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	ManualCheck bool            `json:"manual_check,omitempty"`
	Related     []string        `json:"related_method_keys,omitempty"`
}

// SemanticAssessment is per-method decompilation correctness beyond syntax.
type SemanticAssessment struct {
	Ref                MethodRef          `json:"ref"`
	SyntacticallyValid bool               `json:"syntactically_valid"`
	BehaviorallyEquiv  bool               `json:"behaviorally_equivalent"`
	Confidence         SemanticConfidence `json:"semantic_confidence"`
	Reasons            []string           `json:"reasons,omitempty"`
	SmaliEvidence      []string           `json:"smali_evidence,omitempty"`
	DisagreeingTools   []string           `json:"disagreeing_tools,omitempty"`
}

// SplitOrigin records which package split an artifact came from.
type SplitOrigin struct {
	Name     string   `json:"name"` // base, config.arm64_v8a, …
	Path     string   `json:"path"` // path to split APK
	Kind     string   `json:"kind"` // base | abi | density | locale | feature | unknown
	SHA256   string   `json:"sha256,omitempty"`
	DEXFiles []string `json:"dex_files,omitempty"`
	Libs     []string `json:"native_libs,omitempty"`
}

// BundleInfo describes a logical application assembled from one or more packages.
type BundleInfo struct {
	Format      string        `json:"format"` // apk | split_apk | xapk | apks | apkm | aab | dir
	LogicalPath string        `json:"logical_path"`
	BaseAPK     string        `json:"base_apk,omitempty"`
	Splits      []SplitOrigin `json:"splits,omitempty"`
	Notes       []string      `json:"notes,omitempty"`
}

// NativeInventoryEntry is one .so with optional symbol / JNI hints.
type NativeInventoryEntry struct {
	NativeLib
	Split           string   `json:"split,omitempty"`
	ExportedSymbols []string `json:"exported_symbols,omitempty"`
	JNISymbols      []string `json:"jni_symbols,omitempty"`
	Note            string   `json:"note,omitempty"`
}

// JNIMapping links a Java/Kotlin native declaration to a .so / JNI symbol when known.
type JNIMapping struct {
	ClassName  string        `json:"class"`
	Method     string        `json:"method"`
	Descriptor string        `json:"descriptor,omitempty"`
	Library    string        `json:"library,omitempty"` // libfoo.so
	JNISymbol  string        `json:"jni_symbol,omitempty"`
	Evidence   string        `json:"evidence,omitempty"`
	EClass     EvidenceClass `json:"evidence_class"`
	Split      string        `json:"split,omitempty"`
}

// GraphNode is a node in the evidence graph.
type GraphNode struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"` // apk|manifest|dex|class|method|smali|decompiled|resource|native|jni|runtime|finding
	Label    string            `json:"label"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	ParentID string            `json:"parent_id,omitempty"`
}

// GraphEdge connects evidence nodes.
type GraphEdge struct {
	From  string        `json:"from"`
	To    string        `json:"to"`
	Rel   string        `json:"rel"` // contains|declares|decompiles_to|maps_to|observes|supports
	Class EvidenceClass `json:"evidence_class,omitempty"`
}

// EvidenceGraph is the navigable evidence structure for humans and AI.
type EvidenceGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// RuntimeObservation is explicitly tagged RUNTIME_OBSERVATION.
type RuntimeObservation struct {
	Kind    string        `json:"kind"`
	Message string        `json:"message"`
	Class   EvidenceClass `json:"evidence_class"` // always RUNTIME_OBSERVATION
	Target  string        `json:"target,omitempty"`
	Status  string        `json:"status,omitempty"`
	Note    string        `json:"note,omitempty"` // e.g. NOT OBSERVED ≠ ABSENT
}

// HuntReport is the shareable one-command hunt artifact payload.
type HuntReport struct {
	SchemaVersion   string                 `json:"schema_version"`
	ToolVersion     string                 `json:"tool_version"`
	GeneratedAt     string                 `json:"generated_at"`
	APK             APKInfo                `json:"apk"`
	Bundle          *BundleInfo            `json:"bundle,omitempty"`
	Summary         AnalysisSummary        `json:"summary"`
	Findings        []Finding              `json:"findings"`
	Secrets         []Finding              `json:"hardcoded_secrets,omitempty"`
	InterestingAPIs []Finding              `json:"interesting_apis,omitempty"`
	Disagreements   []MethodResult         `json:"decompiler_disagreements,omitempty"`
	Semantic        []SemanticAssessment   `json:"semantic_confidence,omitempty"`
	Native          []NativeInventoryEntry `json:"native_libraries,omitempty"`
	JNI             []JNIMapping           `json:"jni_relationships,omitempty"`
	RuntimeObs      []RuntimeObservation   `json:"runtime_observations,omitempty"`
	Graph           *EvidenceGraph         `json:"evidence_graph,omitempty"`
	Methods         []MethodResult         `json:"methods,omitempty"`
	Notes           []string               `json:"notes,omitempty"`
	Limitations     []string               `json:"limitations,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// CIResult is machine-readable CI output.
type CIResult struct {
	OK            bool     `json:"ok"`
	ExitCode      int      `json:"exit_code"`
	FailedRules   []string `json:"failed_rules,omitempty"`
	FindingsHigh  int      `json:"findings_high"`
	FindingsCrit  int      `json:"findings_critical"`
	SecretsHigh   int      `json:"secrets_high"`
	Disagreements int      `json:"decompiler_disagreements"`
	SemanticLow   int      `json:"semantic_below_threshold"`
	ReportPath    string   `json:"report_path,omitempty"`
	JSONPath      string   `json:"json_path,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}
