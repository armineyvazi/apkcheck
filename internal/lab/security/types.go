// Package security provides authorized Android security-testing templates,
// observations (not auto-vuln claims), evidence export, and harness helpers.
//
// All capabilities are for apps/devices the operator owns or is authorized to test.
// The system reports Observations with evidence — never automatic "this is a vuln" claims.
package security

import (
	"time"
)

// Severity for observations — never treated as confirmed CVSS without tester review.
type Severity string

const (
	SeverityInfo       Severity = "informational"
	SeverityPotential  Severity = "potential"
	SeverityNeedsReview Severity = "needs_review"
)

// Category groups security templates.
type Category string

const (
	CatLifecycle   Category = "app_lifecycle"
	CatIPC         Category = "ipc_components"
	CatStorage     Category = "storage"
	CatNetwork     Category = "network"
	CatAuthn       Category = "authentication"
	CatAuthz       Category = "authorization"
	CatWebView     Category = "webview"
	CatDeepLink    Category = "deep_links"
	CatClipboard   Category = "clipboard"
	CatUI          Category = "screenshots_ui"
	CatRuntime     Category = "runtime_os"
	CatCrypto      Category = "cryptography"
	CatPrivacy     Category = "privacy"
)

// StepKind is a scenario builder / runner primitive.
type StepKind string

const (
	StepAnalyzeManifest   StepKind = "analyze_manifest"
	StepListExported      StepKind = "list_exported"
	StepLaunchComponent   StepKind = "launch_component"
	StepSendIntent        StepKind = "send_intent"
	StepOpenDeepLink      StepKind = "open_deep_link"
	StepLaunchApp         StepKind = "launch_app"
	StepBackgroundApp     StepKind = "background_app"
	StepForceStop         StepKind = "force_stop"
	StepStartMonitor      StepKind = "start_monitor"
	StepCaptureLogs       StepKind = "capture_logs"
	StepCaptureNetwork    StepKind = "capture_network"
	StepCaptureScreenshot StepKind = "capture_screenshot"
	StepInspectStorage    StepKind = "inspect_storage"
	StepInspectPermissions StepKind = "inspect_permissions"
	StepWait              StepKind = "wait"
	StepHarnessInstall    StepKind = "harness_install"
	StepHarnessProbe      StepKind = "harness_probe"
	StepRecordObservation StepKind = "record_observation"
	StepUserAction        StepKind = "user_action" // placeholder for manual/UI automation
	StepAssertProcess     StepKind = "assert_process"
)

// Step is one executable or documentary step in a template.
type Step struct {
	Kind    StepKind          `json:"kind"`
	Label   string            `json:"label"`
	Params  map[string]string `json:"params,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// Template is a reusable security test definition.
type Template struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    Category  `json:"category"`
	Description string    `json:"description"`
	StaticOnly  bool      `json:"static_only,omitempty"`
	RequiresDevice bool   `json:"requires_device,omitempty"`
	RequiresHarness bool  `json:"requires_harness,omitempty"`
	Steps       []Step    `json:"steps"`
	CLIHint     string    `json:"cli_hint,omitempty"`
}

// Preset composes template IDs.
type Preset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TemplateIDs []string `json:"template_ids"`
}

// Observation is evidence-backed — not an automatic vulnerability claim.
type Observation struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Severity     Severity          `json:"severity"`
	Category     Category          `json:"category,omitempty"`
	TemplateID   string            `json:"template_id,omitempty"`
	ArtifactID   string            `json:"artifact_id,omitempty"`
	Package      string            `json:"package,omitempty"`
	Component    string            `json:"component,omitempty"`
	Summary      string            `json:"summary"`
	Evidence     []EvidenceItem    `json:"evidence,omitempty"`
	Reproduction []string          `json:"reproduction,omitempty"`
	Runtime      string            `json:"runtime,omitempty"`
	TesterNotes  string            `json:"tester_notes,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	Meta         map[string]string `json:"meta,omitempty"`
}

// EvidenceItem is one piece of collected evidence.
type EvidenceItem struct {
	Kind    string `json:"kind"` // manifest|log|intent|network|screenshot|runtime|stack|file
	Path    string `json:"path,omitempty"`
	Label   string `json:"label,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

// TimelineEvent for background / security run visualization.
type TimelineEvent struct {
	OffsetMS int64  `json:"offset_ms"`
	At       time.Time `json:"at"`
	Type     string `json:"type"`
	Message  string `json:"message"`
}

// RunReport is the result of executing a template against a target.
type RunReport struct {
	ID         string          `json:"id"`
	TemplateID string          `json:"template_id"`
	ArtifactID string          `json:"artifact_id"`
	OK         bool            `json:"ok"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	EndedAt    time.Time       `json:"ended_at"`
	StepsDone  []string        `json:"steps_done,omitempty"`
	Timeline   []TimelineEvent `json:"timeline,omitempty"`
	ObservationIDs []string    `json:"observation_ids,omitempty"`
	EvidenceDir string         `json:"evidence_dir,omitempty"`
}

// ManifestReview is a security-relevant manifest summary (review, not vuln claim).
type ManifestReview struct {
	Package            string   `json:"package"`
	VersionName        string   `json:"version_name,omitempty"`
	VersionCode        int64    `json:"version_code,omitempty"`
	Debuggable         *bool    `json:"debuggable,omitempty"`
	AllowBackup        *bool    `json:"allow_backup,omitempty"`
	Permissions        []string `json:"permissions,omitempty"`
	Activities         []string `json:"activities,omitempty"`
	Services           []string `json:"services,omitempty"`
	Receivers          []string `json:"receivers,omitempty"`
	Providers          []string `json:"providers,omitempty"`
	ExportedActivities []string `json:"exported_activities,omitempty"`
	ExportedServices   []string `json:"exported_services,omitempty"`
	ExportedReceivers  []string `json:"exported_receivers,omitempty"`
	ExportedProviders  []string `json:"exported_providers,omitempty"`
	DeepLinks          []string `json:"deep_links,omitempty"`
	ReviewNotes        []string `json:"review_notes,omitempty"` // things to review
	Source             string   `json:"source,omitempty"`
}
