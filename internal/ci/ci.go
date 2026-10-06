// Package ci evaluates analysis results against fail thresholds for CI/CD.
package ci

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/armin/apkcheck/pkg/model"
)

// Config is the CI gate configuration.
type Config struct {
	Security struct {
		FailOn string `yaml:"fail_on"` // low|medium|high|critical
	} `yaml:"security"`
	Decompiler struct {
		DisagreementThreshold int `yaml:"disagreement_threshold"`
	} `yaml:"decompiler"`
	Semantic struct {
		MinimumConfidence string `yaml:"minimum_confidence"` // high|medium|low
	} `yaml:"semantic"`
	Secrets struct {
		FailOnHigh bool `yaml:"fail_on_high"`
	} `yaml:"secrets"`
}

// Default returns sensible CI defaults.
func Default() Config {
	var c Config
	c.Security.FailOn = "high"
	c.Decompiler.DisagreementThreshold = 10
	c.Semantic.MinimumConfidence = "medium"
	c.Secrets.FailOnHigh = true
	return c
}

// LoadYAML loads CI config from a file; missing file → defaults.
func LoadYAML(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse ci config: %w", err)
	}
	if c.Security.FailOn == "" {
		c.Security.FailOn = "high"
	}
	if c.Decompiler.DisagreementThreshold == 0 {
		c.Decompiler.DisagreementThreshold = 10
	}
	if c.Semantic.MinimumConfidence == "" {
		c.Semantic.MinimumConfidence = "medium"
	}
	return c, nil
}

// Evaluate returns a CIResult and suggested process exit code.
func Evaluate(r *model.AnalysisResult, cfg Config) model.CIResult {
	res := model.CIResult{OK: true, ExitCode: 0}
	if r == nil {
		res.OK = false
		res.ExitCode = 2
		res.FailedRules = []string{"analysis_failed"}
		return res
	}

	minSev := parseSev(cfg.Security.FailOn)
	for _, f := range r.Findings {
		if f.Category == model.CatHardcodedSecret {
			if sevRank(f.Severity) >= sevRank(model.SeverityHigh) {
				res.SecretsHigh++
			}
		}
		if sevRank(f.Severity) >= sevRank(model.SeverityHigh) {
			res.FindingsHigh++
		}
		if f.Severity == model.SeverityCritical {
			res.FindingsCrit++
		}
		if sevRank(f.Severity) >= minSev && f.Class == model.EvidenceStatic {
			// Only fail on STATIC_EVIDENCE at threshold — not pure INFERENCE
			rule := fmt.Sprintf("security:%s:%s", f.Severity, f.ID)
			if f.Category == model.CatHardcodedSecret && cfg.Secrets.FailOnHigh && sevRank(f.Severity) >= sevRank(model.SeverityHigh) {
				res.FailedRules = append(res.FailedRules, rule)
			} else if f.Category != model.CatHardcodedSecret && f.Category != model.CatDecompilerDisagree {
				if sevRank(f.Severity) >= minSev {
					res.FailedRules = append(res.FailedRules, rule)
				}
			}
		}
	}

	res.Disagreements = r.Summary.MethodsDisagreement
	if cfg.Decompiler.DisagreementThreshold > 0 && res.Disagreements > cfg.Decompiler.DisagreementThreshold {
		res.FailedRules = append(res.FailedRules,
			fmt.Sprintf("decompiler:disagreement_threshold:%d>%d", res.Disagreements, cfg.Decompiler.DisagreementThreshold))
	}

	minSem := parseSem(cfg.Semantic.MinimumConfidence)
	for _, s := range r.Semantic {
		if semRank(s.Confidence) < minSem {
			res.SemanticLow++
		}
	}
	// Fail if a large fraction of analyzed methods are below threshold
	if len(r.Semantic) > 0 && res.SemanticLow > len(r.Semantic)/2 && minSem > semRank(model.SemanticLow) {
		res.FailedRules = append(res.FailedRules,
			fmt.Sprintf("semantic:majority_below_%s:%d", cfg.Semantic.MinimumConfidence, res.SemanticLow))
	}

	if len(res.FailedRules) > 0 {
		res.OK = false
		res.ExitCode = 1
	}
	res.Notes = append(res.Notes,
		"CI fails on STATIC_EVIDENCE thresholds; INFERENCE alone does not fail the build.",
		"NOT OBSERVED ≠ ABSENT — runtime absence is never a pass criterion.",
	)
	return res
}

func parseSev(s string) int {
	return sevRank(model.Severity(strings.ToLower(s)))
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 3
	}
}

func parseSem(s string) int {
	switch strings.ToLower(s) {
	case "high":
		return semRank(model.SemanticHigh)
	case "medium":
		return semRank(model.SemanticMedium)
	case "low":
		return semRank(model.SemanticLow)
	default:
		return semRank(model.SemanticMedium)
	}
}

func semRank(c model.SemanticConfidence) int {
	switch c {
	case model.SemanticHigh:
		return 3
	case model.SemanticMedium:
		return 2
	case model.SemanticLow:
		return 1
	default:
		return 0
	}
}
