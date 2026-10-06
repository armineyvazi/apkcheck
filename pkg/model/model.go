// Package model defines the public, versioned data types used by apkcheck
// reports and the analysis pipeline.
package model

import "time"

// SchemaVersion is the version of the JSON report schema.
const SchemaVersion = "2.0.0"

// Confidence classifies how well a reconstruction aligns with DEX/Smali.
type Confidence string

const (
	ConfidenceConsistent           Confidence = "CONSISTENT"
	ConfidencePartiallyConsistent  Confidence = "PARTIALLY_CONSISTENT"
	ConfidenceDisagreement         Confidence = "DISAGREEMENT"
	ConfidenceUnresolved           Confidence = "UNRESOLVED"
	ConfidenceSourceOfTruth        Confidence = "SOURCE_OF_TRUTH"
	ConfidenceToolFailure          Confidence = "TOOL_FAILURE"
	ConfidenceParseFailure         Confidence = "PARSE_FAILURE"
	ConfidenceInsufficientEvidence Confidence = "INSUFFICIENT_EVIDENCE"
)

// Severity ranks the importance of a disagreement or finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// IssueType categorizes semantic disagreements.
type IssueType string

const (
	IssueCFGDifference         IssueType = "cfg_difference"
	IssueCallDifference        IssueType = "call_difference"
	IssueFieldDifference       IssueType = "field_difference"
	IssueExceptionFlowDiff     IssueType = "exception_flow_difference"
	IssueReturnFlowDiff        IssueType = "return_flow_difference"
	IssueBranchDifference      IssueType = "branch_difference"
	IssueInsufficientEvidence  IssueType = "insufficient_evidence"
	IssueDecompileFailure      IssueType = "decompile_failure"
	IssueParseFailure          IssueType = "parse_failure"
	IssueBooleanExprDifference IssueType = "boolean_expression_difference"
)

// APKInfo holds high-level metadata extracted from an APK.
type APKInfo struct {
	Path               string            `json:"path"`
	SHA256             string            `json:"sha256"`
	Size               int64             `json:"size"`
	Package            string            `json:"package,omitempty"`
	VersionName        string            `json:"version_name,omitempty"`
	VersionCode        int64             `json:"version_code,omitempty"`
	MinSDK             int               `json:"min_sdk,omitempty"`
	TargetSDK          int               `json:"target_sdk,omitempty"`
	Permissions        []string          `json:"permissions,omitempty"`
	Activities         []string          `json:"activities,omitempty"`
	Services           []string          `json:"services,omitempty"`
	Receivers          []string          `json:"receivers,omitempty"`
	Providers          []string          `json:"providers,omitempty"`
	ExportedActivities []string          `json:"exported_activities,omitempty"`
	ExportedServices   []string          `json:"exported_services,omitempty"`
	ExportedReceivers  []string          `json:"exported_receivers,omitempty"`
	ExportedProviders  []string          `json:"exported_providers,omitempty"`
	Debuggable         *bool             `json:"debuggable,omitempty"`
	AllowBackup        *bool             `json:"allow_backup,omitempty"`
	UsesCleartext      *bool             `json:"uses_cleartext_traffic,omitempty"`
	NetworkSecurityCfg string            `json:"network_security_config,omitempty"`
	DEXFiles           []string          `json:"dex_files,omitempty"`
	DEXCount           int               `json:"dex_count"`
	NativeLibs         []NativeLib       `json:"native_libs,omitempty"`
	ABIs               []string          `json:"abis,omitempty"`
	HasResources       bool              `json:"has_resources"`
	HasAssets          bool              `json:"has_assets"`
	Signing            *SigningInfo      `json:"signing,omitempty"`
	SplitOrigins       map[string]string `json:"split_origins,omitempty"` // artifact path → split name
}

// NativeLib describes a packaged shared library.
type NativeLib struct {
	Path string `json:"path"`
	ABI  string `json:"abi"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// SigningInfo captures basic signing metadata when available.
type SigningInfo struct {
	V1Signed bool     `json:"v1_signed"`
	V2Signed bool     `json:"v2_signed"`
	V3Signed bool     `json:"v3_signed"`
	Certs    []string `json:"certs,omitempty"`
	Note     string   `json:"note,omitempty"`
}

// ToolStatus reports availability of an external tool.
type ToolStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
	Required  bool   `json:"required"`
	Error     string `json:"error,omitempty"`
}

// DoctorReport is the output of `apkcheck doctor`.
type DoctorReport struct {
	Tools []ToolStatus `json:"tools"`
	OK    bool         `json:"ok"`
}

// MethodRef uniquely identifies a method.
type MethodRef struct {
	Class      string   `json:"class"`
	Name       string   `json:"method"`
	Parameters []string `json:"parameters,omitempty"`
	ReturnType string   `json:"return_type,omitempty"`
	Descriptor string   `json:"descriptor,omitempty"`
}

// String returns a human-readable method identity.
func (m MethodRef) String() string {
	if m.Descriptor != "" {
		return m.Class + "." + m.Name + m.Descriptor
	}
	params := ""
	for i, p := range m.Parameters {
		if i > 0 {
			params += ","
		}
		params += p
	}
	ret := m.ReturnType
	if ret == "" {
		ret = "?"
	}
	return m.Class + "." + m.Name + "(" + params + ")" + ret
}

// Key returns a stable map key for the method.
func (m MethodRef) Key() string {
	if m.Descriptor != "" {
		return m.Class + "->" + m.Name + m.Descriptor
	}
	return m.Class + "->" + m.Name
}

// Issue describes a semantic disagreement or analysis limitation.
type Issue struct {
	Type        IssueType `json:"type"`
	Severity    Severity  `json:"severity"`
	Decompiler  string    `json:"decompiler,omitempty"`
	Message     string    `json:"message"`
	Evidence    string    `json:"evidence,omitempty"`
	ManualCheck bool      `json:"manual_check,omitempty"`
}

// DecompilerMethodResult holds per-decompiler analysis for one method.
type DecompilerMethodResult struct {
	Name       string     `json:"name"`
	Status     Confidence `json:"status"`
	Issues     []Issue    `json:"issues,omitempty"`
	SourcePath string     `json:"source_path,omitempty"`
	Note       string     `json:"note,omitempty"`
}

// MethodResult is the cross-decompiler comparison for one method.
type MethodResult struct {
	Ref                MethodRef                         `json:"ref"`
	Status             Confidence                        `json:"status"`
	SecurityRelevant   bool                              `json:"security_relevant,omitempty"`
	SecurityTags       []string                          `json:"security_tags,omitempty"`
	Smali              *SmaliSummary                     `json:"smali,omitempty"`
	Decompilers        map[string]DecompilerMethodResult `json:"decompilers"`
	Issues             []Issue                           `json:"issues,omitempty"`
	Verdict            string                            `json:"verdict"`
	SemanticConfidence SemanticConfidence                `json:"semantic_confidence,omitempty"`
	SemanticNote       string                            `json:"semantic_note,omitempty"`
	SplitOrigin        string                            `json:"split_origin,omitempty"`
	NativeBridge       bool                              `json:"native_bridge,omitempty"`
}

// SmaliSummary is the ground-truth summary derived from Smali/DEX.
type SmaliSummary struct {
	Instructions  int `json:"instructions"`
	BasicBlocks   int `json:"basic_blocks"`
	Branches      int `json:"branches"`
	Calls         int `json:"calls"`
	FieldAccesses int `json:"field_accesses"`
	Returns       int `json:"returns"`
	Throws        int `json:"throws"`
	Exceptions    int `json:"exceptions"`
	Monitors      int `json:"monitors"`
	ObjectCreates int `json:"object_creates"`
	Constants     int `json:"constants"`
}

// AnalysisSummary aggregates analysis outcomes.
type AnalysisSummary struct {
	MethodsAnalyzed     int `json:"methods_analyzed"`
	MethodsConsistent   int `json:"methods_consistent"`
	MethodsPartial      int `json:"methods_partially_consistent"`
	MethodsDisagreement int `json:"methods_disagreement"`
	MethodsUnresolved   int `json:"methods_unresolved"`
	SecurityRelevant    int `json:"security_relevant_methods"`
	ToolFailures        int `json:"tool_failures"`
	ParseFailures       int `json:"parse_failures"`
	SmaliMethodsTotal   int `json:"smali_methods_total,omitempty"`
	SkippedFramework    int `json:"skipped_framework,omitempty"`
	SkippedSynthetic    int `json:"skipped_synthetic,omitempty"`
	SkippedEmpty        int `json:"skipped_empty,omitempty"`
}

// AnalysisResult is the top-level report payload.
type AnalysisResult struct {
	SchemaVersion   string                 `json:"schema_version"`
	ToolVersion     string                 `json:"tool_version"`
	GeneratedAt     time.Time              `json:"generated_at"`
	APK             APKInfo                `json:"apk"`
	Bundle          *BundleInfo            `json:"bundle,omitempty"`
	Tools           []ToolStatus           `json:"tools"`
	Summary         AnalysisSummary        `json:"summary"`
	Methods         []MethodResult         `json:"methods"`
	Findings        []Finding              `json:"findings,omitempty"`
	Semantic        []SemanticAssessment   `json:"semantic_assessments,omitempty"`
	Native          []NativeInventoryEntry `json:"native_inventory,omitempty"`
	JNI             []JNIMapping           `json:"jni_mappings,omitempty"`
	Graph           *EvidenceGraph         `json:"evidence_graph,omitempty"`
	RuntimeObs      []RuntimeObservation   `json:"runtime_observations,omitempty"`
	Runtime         *RuntimeReport         `json:"runtime,omitempty"`
	Focus           string                 `json:"focus,omitempty"`
	Notes           []string               `json:"notes,omitempty"`
	Limitations     []string               `json:"limitations,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// RuntimeReport is a compact runtime-session summary embedded in static reports.
type RuntimeReport struct {
	SessionID    string   `json:"session_id,omitempty"`
	Type         string   `json:"type,omitempty"` // physical-device | emulator
	Connection   string   `json:"connection,omitempty"`
	Host         string   `json:"host,omitempty"`
	HostArch     string   `json:"host_arch,omitempty"`
	AVD          string   `json:"avd,omitempty"`
	Device       string   `json:"device,omitempty"`
	DeviceID     string   `json:"device_id,omitempty"`
	Android      string   `json:"android,omitempty"`
	API          string   `json:"api,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	Screen       string   `json:"screen,omitempty"`
	Crashes      int      `json:"crashes"`
	Permissions  int      `json:"permissions_compared"`
	Network      int      `json:"network_observations"`
	Timeline     int      `json:"timeline_events"`
	Correlations int      `json:"correlations"`
	LogcatPath   string   `json:"logcat_path,omitempty"`
	SessionJSON  string   `json:"session_json,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	Limitations  []string `json:"limitations,omitempty"`
}
