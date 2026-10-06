package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/pkg/model"
)

// ReviewManifest builds a ManifestReview from an artifact (APK path or project dir).
func ReviewManifest(art *lab.Artifact) (*ManifestReview, error) {
	if art == nil {
		return nil, fmt.Errorf("artifact required")
	}
	rev := &ManifestReview{Source: art.Path, Package: art.Package}
	switch art.Kind {
	case lab.KindProject:
		return reviewProject(art.Path, rev)
	case lab.KindOriginalAPK, lab.KindSignedAPK, lab.KindUnsignedAPK:
		return reviewAPK(art.Path, rev)
	default:
		return nil, fmt.Errorf("unsupported kind %s", art.Kind)
	}
}

func reviewProject(dir string, rev *ManifestReview) (*ManifestReview, error) {
	man := filepath.Join(dir, "AndroidManifest.xml")
	data, err := os.ReadFile(man)
	if err != nil {
		return nil, err
	}
	xml := string(data)
	info := &model.APKInfo{}
	apk.EnrichFromManifestYAML(info, xml)
	fillFromInfo(rev, info, xml)
	rev.Source = man
	return rev, nil
}

func reviewAPK(path string, rev *ManifestReview) (*ManifestReview, error) {
	info, err := apk.Inspect(path)
	if err != nil {
		return nil, err
	}
	if info.Package == "" && rev.Package != "" {
		info.Package = rev.Package
	}
	xml := ""
	if tree, err := dumpManifestXMLTree(path); err == nil && tree != "" {
		parseXMLTree(info, &xml, tree)
		rev.Source = path + " (aapt dump xmltree)"
	} else {
		rev.Source = path + " (zip inspect only — install build-tools aapt for full surface)"
		if err != nil {
			rev.ReviewNotes = append(rev.ReviewNotes, "NOTE: aapt xmltree unavailable: "+err.Error())
		}
	}
	fillFromInfo(rev, info, xml)
	return rev, nil
}

func fillFromInfo(rev *ManifestReview, info *model.APKInfo, xml string) {
	if info.Package != "" {
		rev.Package = info.Package
	}
	rev.VersionName = info.VersionName
	rev.VersionCode = info.VersionCode
	rev.Debuggable = info.Debuggable
	rev.AllowBackup = info.AllowBackup
	rev.Permissions = info.Permissions
	rev.Activities = info.Activities
	rev.Services = info.Services
	rev.Receivers = info.Receivers
	rev.Providers = info.Providers
	rev.ExportedActivities = info.ExportedActivities
	rev.ExportedServices = info.ExportedServices
	rev.ExportedReceivers = info.ExportedReceivers
	rev.ExportedProviders = info.ExportedProviders
	if links := extractDeepLinks(xml); len(links) > 0 {
		rev.DeepLinks = links
	}
	notes := buildReviewNotes(rev)
	if len(rev.ReviewNotes) > 0 {
		notes = append(rev.ReviewNotes, notes...)
	}
	rev.ReviewNotes = uniqueStrings(notes)
}

var (
	schemeRE   = regexp.MustCompile(`android:scheme="([^"]+)"`)
	hostRE     = regexp.MustCompile(`android:host="([^"]+)"`)
	dataRE     = regexp.MustCompile(`(?s)<data\b[^>]*/?>`)
	treeElemRE = regexp.MustCompile(`^(\s*)E: ([a-zA-Z0-9_\-\.]+)`)
)

func extractDeepLinks(xml string) []string {
	if xml == "" {
		return nil
	}
	var out []string
	for _, m := range dataRE.FindAllString(xml, -1) {
		sch := schemeRE.FindStringSubmatch(m)
		hst := hostRE.FindStringSubmatch(m)
		switch {
		case len(sch) > 1 && len(hst) > 1:
			out = append(out, sch[1]+"://"+hst[1])
		case len(sch) > 1:
			out = append(out, sch[1]+"://")
		}
	}
	return uniqueStrings(out)
}

func buildReviewNotes(rev *ManifestReview) []string {
	var notes []string
	if rev.Debuggable != nil && *rev.Debuggable {
		notes = append(notes, "REVIEW: android:debuggable=true")
	}
	if rev.AllowBackup != nil && *rev.AllowBackup {
		notes = append(notes, "REVIEW: allowBackup enabled (backup may expose app data on test devices)")
	}
	if n := len(rev.ExportedActivities); n > 0 {
		notes = append(notes, fmt.Sprintf("REVIEW: %d exported activities — verify intended exposure", n))
		for i, name := range rev.ExportedActivities {
			if i >= 15 {
				notes = append(notes, fmt.Sprintf("REVIEW: … +%d more exported activities", n-15))
				break
			}
			notes = append(notes, "EXPORT activity: "+name)
		}
	}
	if n := len(rev.ExportedServices); n > 0 {
		notes = append(notes, fmt.Sprintf("REVIEW: %d exported services", n))
		for i, name := range rev.ExportedServices {
			if i >= 10 {
				break
			}
			notes = append(notes, "EXPORT service: "+name)
		}
	}
	if n := len(rev.ExportedReceivers); n > 0 {
		notes = append(notes, fmt.Sprintf("REVIEW: %d exported receivers", n))
		for i, name := range rev.ExportedReceivers {
			if i >= 10 {
				break
			}
			notes = append(notes, "EXPORT receiver: "+name)
		}
	}
	if n := len(rev.ExportedProviders); n > 0 {
		notes = append(notes, fmt.Sprintf("REVIEW: %d exported providers", n))
		for i, name := range rev.ExportedProviders {
			if i >= 10 {
				break
			}
			notes = append(notes, "EXPORT provider: "+name)
		}
	}
	if len(rev.DeepLinks) > 0 {
		notes = append(notes, fmt.Sprintf("REVIEW: %d deep-link data patterns found", len(rev.DeepLinks)))
		for i, d := range rev.DeepLinks {
			if i >= 12 {
				notes = append(notes, fmt.Sprintf("REVIEW: … +%d more deep links", len(rev.DeepLinks)-12))
				break
			}
			notes = append(notes, "DEEPLINK: "+d)
		}
	}
	for _, p := range rev.Permissions {
		pl := strings.ToLower(p)
		if strings.Contains(pl, "read_sms") || strings.Contains(pl, "receive_sms") ||
			strings.Contains(pl, "access_fine_location") || strings.Contains(pl, "record_audio") ||
			strings.Contains(pl, "camera") || strings.Contains(pl, "read_contacts") ||
			strings.Contains(pl, "request_install_packages") || strings.Contains(pl, "install_packages") {
			notes = append(notes, "REVIEW: sensitive permission declared: "+p)
		}
	}
	if len(notes) == 0 {
		notes = append(notes, "No high-signal static review notes from available manifest fields (NOT OBSERVED ≠ ABSENT)")
	}
	return uniqueStrings(notes)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dumpManifestXMLTree(apkPath string) (string, error) {
	aapt := findOnPathOrBuildTools("aapt")
	if aapt == "" {
		return "", fmt.Errorf("aapt not found in PATH or ANDROID_HOME/build-tools")
	}
	cmd := exec.Command(aapt, "dump", "xmltree", apkPath, "AndroidManifest.xml")
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("aapt dump xmltree: %w\n%s", err, b)
	}
	return string(b), nil
}

type treeNode struct {
	tag, name, exported string
	indent              int
	hasFilter           bool
	scheme, host        string
}

// parseXMLTree fills info + synthesizes minimal XML for deep-link extraction.
func parseXMLTree(info *model.APKInfo, xmlOut *string, tree string) {
	var stack []treeNode
	var deepXML strings.Builder
	deepXML.WriteString("<manifest>")

	flush := func(n treeNode) {
		switch n.tag {
		case "activity", "activity-alias":
			if n.name == "" {
				return
			}
			info.Activities = append(info.Activities, n.name)
			exp := strings.ToLower(n.exported)
			if exp == "true" || (exp != "false" && n.hasFilter) {
				info.ExportedActivities = append(info.ExportedActivities, n.name)
			}
		case "service":
			if n.name == "" {
				return
			}
			info.Services = append(info.Services, n.name)
			exp := strings.ToLower(n.exported)
			if exp == "true" || (exp != "false" && n.hasFilter) {
				info.ExportedServices = append(info.ExportedServices, n.name)
			}
		case "receiver":
			if n.name == "" {
				return
			}
			info.Receivers = append(info.Receivers, n.name)
			exp := strings.ToLower(n.exported)
			if exp == "true" || (exp != "false" && n.hasFilter) {
				info.ExportedReceivers = append(info.ExportedReceivers, n.name)
			}
		case "provider":
			if n.name == "" {
				return
			}
			info.Providers = append(info.Providers, n.name)
			if strings.ToLower(n.exported) == "true" {
				info.ExportedProviders = append(info.ExportedProviders, n.name)
			}
		case "uses-permission":
			if n.name != "" {
				info.Permissions = append(info.Permissions, n.name)
			}
		case "data":
			if n.scheme != "" {
				if n.host != "" {
					fmt.Fprintf(&deepXML, `<data android:scheme="%s" android:host="%s"/>`, n.scheme, n.host)
				} else {
					fmt.Fprintf(&deepXML, `<data android:scheme="%s"/>`, n.scheme)
				}
			}
		}
	}

	for _, line := range strings.Split(tree, "\n") {
		if m := treeElemRE.FindStringSubmatch(line); len(m) > 2 {
			indent := len(m[1])
			tag := m[2]
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				flush(top)
			}
			if tag == "intent-filter" && len(stack) > 0 {
				stack[len(stack)-1].hasFilter = true
			}
			stack = append(stack, treeNode{tag: tag, indent: indent})
			continue
		}

		// Manifest-level attrs (empty stack)
		if len(stack) == 0 {
			if strings.Contains(line, `package="`) {
				if v := xmltreeStringAttr(line, "package"); v != "" && info.Package == "" {
					info.Package = v
				}
			}
			if strings.Contains(line, "versionName") {
				if v := xmltreeStringAttr(line, "versionName"); v != "" {
					info.VersionName = v
				}
			}
			if strings.Contains(line, "versionCode") {
				if v := xmltreeHexOrInt(line, "versionCode"); v > 0 {
					info.VersionCode = v
				}
			}
			continue
		}

		cur := &stack[len(stack)-1]
		if strings.Contains(line, "name(") || strings.Contains(line, "android:name") || strings.Contains(line, `A: name=`) {
			if v := xmltreeStringAttr(line, "name"); v != "" {
				cur.name = v
			}
		}
		if strings.Contains(line, "exported") {
			if v := xmltreeStringAttr(line, "exported"); v != "" {
				cur.exported = v
			} else if b := xmltreeBoolAttr(line, "exported"); b != nil {
				if *b {
					cur.exported = "true"
				} else {
					cur.exported = "false"
				}
			}
		}
		if strings.Contains(line, "scheme") {
			if v := xmltreeStringAttr(line, "scheme"); v != "" {
				cur.scheme = v
			}
		}
		if strings.Contains(line, "host") {
			if v := xmltreeStringAttr(line, "host"); v != "" {
				cur.host = v
			}
		}
		if cur.tag == "application" {
			if strings.Contains(line, "debuggable") {
				if b := xmltreeBoolAttr(line, "debuggable"); b != nil {
					info.Debuggable = b
				}
			}
			if strings.Contains(line, "allowBackup") {
				if b := xmltreeBoolAttr(line, "allowBackup"); b != nil {
					info.AllowBackup = b
				}
			}
		}
		if cur.tag == "uses-sdk" {
			if strings.Contains(line, "minSdkVersion") {
				if v := xmltreeHexOrInt(line, "minSdkVersion"); v > 0 {
					info.MinSDK = int(v)
				}
			}
			if strings.Contains(line, "targetSdkVersion") {
				if v := xmltreeHexOrInt(line, "targetSdkVersion"); v > 0 {
					info.TargetSDK = int(v)
				}
			}
		}
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		flush(top)
	}
	deepXML.WriteString("</manifest>")
	if xmlOut != nil {
		*xmlOut = deepXML.String()
	}

	info.Activities = uniqueStrings(info.Activities)
	info.Services = uniqueStrings(info.Services)
	info.Receivers = uniqueStrings(info.Receivers)
	info.Providers = uniqueStrings(info.Providers)
	info.Permissions = uniqueStrings(info.Permissions)
	info.ExportedActivities = uniqueStrings(info.ExportedActivities)
	info.ExportedServices = uniqueStrings(info.ExportedServices)
	info.ExportedReceivers = uniqueStrings(info.ExportedReceivers)
	info.ExportedProviders = uniqueStrings(info.ExportedProviders)
}

func xmltreeStringAttr(line, key string) string {
	if i := strings.Index(line, `Raw: "`); i >= 0 {
		rest := line[i+6:]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j]
		}
	}
	re := regexp.MustCompile(regexp.QuoteMeta(key) + `="([^"]*)"`)
	if m := re.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	return ""
}

func xmltreeBoolAttr(line, key string) *bool {
	if !strings.Contains(strings.ToLower(line), strings.ToLower(key)) {
		return nil
	}
	if strings.Contains(line, "0xffffffff") || strings.Contains(line, `="true"`) || strings.Contains(line, `Raw: "true"`) {
		v := true
		return &v
	}
	if strings.Contains(line, ")0x0") || strings.Contains(line, `="false"`) || strings.Contains(line, `Raw: "false"`) {
		v := false
		return &v
	}
	return nil
}

func xmltreeHexOrInt(line, key string) int64 {
	if !strings.Contains(line, key) {
		return 0
	}
	re := regexp.MustCompile(`\(type [^)]*\)(0x[0-9a-fA-F]+)`)
	if m := re.FindStringSubmatch(line); len(m) > 1 {
		v, err := strconv.ParseInt(m[1], 0, 64)
		if err == nil {
			return v
		}
	}
	if v := xmltreeStringAttr(line, key); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}
