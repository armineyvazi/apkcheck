package recording

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/armin/apkcheck/internal/lab/session"
)

// RetentionPolicy controls automatic recording cleanup (§35.23).
type RetentionPolicy string

const (
	RetainEverything RetentionPolicy = "everything"
	Retain7Days      RetentionPolicy = "7d"
	Retain30Days     RetentionPolicy = "30d"
	RetainFailedOnly RetentionPolicy = "failed_only"
	RetainSavedOnly  RetentionPolicy = "saved_only"
)

// RetentionConfig is persisted under the lab workspace.
type RetentionConfig struct {
	Policy RetentionPolicy `json:"policy"`
}

func retentionPath(root string) string {
	return filepath.Join(root, "recordings", "retention.json")
}

// LoadRetention reads retention config (default: everything).
func LoadRetention(root string) RetentionConfig {
	data, err := os.ReadFile(retentionPath(root))
	if err != nil {
		return RetentionConfig{Policy: RetainEverything}
	}
	var c RetentionConfig
	if json.Unmarshal(data, &c) != nil || c.Policy == "" {
		return RetentionConfig{Policy: RetainEverything}
	}
	return c
}

// SaveRetention persists retention config.
func SaveRetention(root string, c RetentionConfig) error {
	if c.Policy == "" {
		c.Policy = RetainEverything
	}
	_ = os.MkdirAll(filepath.Join(root, "recordings"), 0o750)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(retentionPath(root), data, 0o640)
}

// CleanupResult summarizes deletions.
type CleanupResult struct {
	Deleted []string `json:"deleted"`
	Kept    int      `json:"kept"`
	Policy  string   `json:"policy"`
	Note    string   `json:"note,omitempty"`
}

// Cleanup applies retention. Bookmarked / manually saved recordings are always kept.
func (m *Manager) Cleanup(sessions *session.Manager) (*CleanupResult, error) {
	cfg := LoadRetention(m.Root)
	res := &CleanupResult{Deleted: []string{}, Policy: string(cfg.Policy)}
	if cfg.Policy == RetainEverything {
		res.Note = "policy=everything — nothing deleted"
		list, _ := m.List()
		res.Kept = len(list)
		return res, nil
	}
	list, err := m.List()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, art := range list {
		keep := false
		var run *session.Run
		if sessions != nil && art.RunID != "" {
			if ev, _ := sessions.ListEvents(art.RunID); ev != nil {
				for _, e := range ev {
					if e.Bookmark {
						keep = true
						break
					}
				}
			}
			if r, rerr := sessions.Get(art.RunID); rerr == nil {
				run = r
				if run.Meta != nil && run.Meta["saved"] == "true" {
					keep = true
				}
			}
		}
		age := now.Sub(art.StartedAt)
		switch cfg.Policy {
		case Retain7Days:
			if age <= 7*24*time.Hour {
				keep = true
			}
		case Retain30Days:
			if age <= 30*24*time.Hour {
				keep = true
			}
		case RetainFailedOnly:
			if run != nil && (run.Status == session.StatusFailed || run.Result == "FAILED") {
				keep = true
			}
		case RetainSavedOnly:
			// only bookmarks / meta.saved
		}
		if keep {
			res.Kept++
			continue
		}
		dir := filepath.Join(m.Root, "recordings", art.ID)
		if err := os.RemoveAll(dir); err == nil {
			res.Deleted = append(res.Deleted, art.ID)
		}
	}
	return res, nil
}

// ParseRetention maps UI/API strings to policy.
func ParseRetention(s string) RetentionPolicy {
	switch s {
	case "7d", "7", "last_7_days":
		return Retain7Days
	case "30d", "30", "last_30_days":
		return Retain30Days
	case "failed", "failed_only", "failed_tests_only":
		return RetainFailedOnly
	case "saved", "saved_only", "manual":
		return RetainSavedOnly
	default:
		return RetainEverything
	}
}

// DescribeRetention returns a short human string.
func DescribeRetention(p RetentionPolicy) string {
	switch p {
	case Retain7Days:
		return "last 7 days (+ bookmarked)"
	case Retain30Days:
		return "last 30 days (+ bookmarked)"
	case RetainFailedOnly:
		return "failed tests only (+ bookmarked)"
	case RetainSavedOnly:
		return "manually saved / bookmarked only"
	default:
		return "keep everything"
	}
}
