// Package compare builds original vs rebuilt validation comparisons.
package compare

import (
	"fmt"

	"github.com/armin/apkcheck/internal/lab"
)

// Metric is one comparable measurement (only real collected data).
type Metric struct {
	Name   string `json:"name"`
	Left   string `json:"left"`
	Right  string `json:"right"`
	Equal  bool   `json:"equal"`
	Detail string `json:"detail,omitempty"`
}

// Report compares two artifacts and optional validation results.
type Report struct {
	LeftID   string   `json:"left_id"`
	RightID  string   `json:"right_id"`
	LeftKind string   `json:"left_kind"`
	RightKind string  `json:"right_kind"`
	Metrics  []Metric `json:"metrics"`
}

// Artifacts compares metadata of two lineage nodes.
func Artifacts(left, right *lab.Artifact) *Report {
	r := &Report{
		LeftID: left.ID, RightID: right.ID,
		LeftKind: string(left.Kind), RightKind: string(right.Kind),
	}
	r.Metrics = append(r.Metrics,
		strMetric("package", left.Package, right.Package),
		strMetric("sha256", left.SHA256, right.SHA256),
		strMetric("kind", string(left.Kind), string(right.Kind)),
	)
	return r
}

// ValidateResults compares two ValidateResult stage outcomes.
func ValidateResults(leftArt, rightArt *lab.Artifact, left, right *lab.ValidateResult) *Report {
	r := Artifacts(leftArt, rightArt)
	if left == nil || right == nil {
		r.Metrics = append(r.Metrics, Metric{
			Name: "validation", Left: fmt.Sprintf("%v", left != nil), Right: fmt.Sprintf("%v", right != nil),
			Equal: left != nil && right != nil, Detail: "one or both validations missing",
		})
		return r
	}
	r.Metrics = append(r.Metrics, Metric{
		Name: "overall_ok", Left: fmt.Sprintf("%v", left.OK), Right: fmt.Sprintf("%v", right.OK),
		Equal: left.OK == right.OK,
	})
	stageMap := func(res *lab.ValidateResult) map[string]lab.ValidateStage {
		m := map[string]lab.ValidateStage{}
		for _, s := range res.Stages {
			m[s.Name] = s
		}
		return m
	}
	lm, rm := stageMap(left), stageMap(right)
	names := map[string]struct{}{}
	for n := range lm {
		names[n] = struct{}{}
	}
	for n := range rm {
		names[n] = struct{}{}
	}
	for name := range names {
		ls, lok := lm[name]
		rs, rok := rm[name]
		lv, rv := "missing", "missing"
		if lok {
			lv = fmt.Sprintf("%v", ls.OK)
			if ls.Error != "" {
				lv += ":" + ls.Error
			}
		}
		if rok {
			rv = fmt.Sprintf("%v", rs.OK)
			if rs.Error != "" {
				rv += ":" + rs.Error
			}
		}
		r.Metrics = append(r.Metrics, Metric{
			Name: "stage:" + name, Left: lv, Right: rv,
			Equal: lok && rok && ls.OK == rs.OK,
		})
	}
	return r
}

func strMetric(name, a, b string) Metric {
	return Metric{Name: name, Left: a, Right: b, Equal: a == b}
}
