// Package scenarios runs limited runtime action sequences (launch/wait/tap text).
package scenarios

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/launcher"
	"github.com/armin/apkcheck/internal/runtime/timeline"
)

// Action is one scenario step.
//
// YAML accepts both compact and structured forms:
//
//   - launch
//   - wait: 10s
//   - tap: Login
//   - tap: { text: Login }
//   - input: { text: pizza }
//   - shell: "am ..."
type Action struct {
	Launch bool          `yaml:"launch,omitempty" json:"launch,omitempty"`
	Wait   time.Duration `yaml:"wait,omitempty" json:"wait,omitempty"`
	Tap    string        `yaml:"tap,omitempty" json:"tap,omitempty"`
	Input  string        `yaml:"input,omitempty" json:"input,omitempty"`
	Shell  string        `yaml:"shell,omitempty" json:"shell,omitempty"`
	// Prompt blocks the Lab scenario engine until UI/API/MCP fills a value
	// (phone|otp|pin|text|choice), then types it via `input text` or taps a choice.
	Prompt        string   `yaml:"prompt,omitempty" json:"prompt,omitempty"`
	PromptLabel   string   `yaml:"prompt_label,omitempty" json:"prompt_label,omitempty"`
	PromptChoices []string `yaml:"prompt_choices,omitempty" json:"prompt_choices,omitempty"`
}

// UnmarshalYAML supports string shorthand ("launch") and nested tap/input maps.
func (a *Action) UnmarshalYAML(value *yaml.Node) error {
	*a = Action{}
	switch value.Kind {
	case yaml.ScalarNode:
		switch strings.ToLower(strings.TrimSpace(value.Value)) {
		case "launch":
			a.Launch = true
			return nil
		case "":
			return nil
		default:
			return fmt.Errorf("unknown scenario action %q (expected launch|wait|tap|input|shell)", value.Value)
		}
	case yaml.MappingNode:
		var raw struct {
			Launch        *bool            `yaml:"launch"`
			Wait          flexibleDuration `yaml:"wait"`
			Tap           yaml.Node        `yaml:"tap"`
			Input         yaml.Node        `yaml:"input"`
			Shell         string           `yaml:"shell"`
			Prompt        string           `yaml:"prompt"`
			PromptLabel   string           `yaml:"prompt_label"`
			PromptChoices []string         `yaml:"prompt_choices"`
		}
		if err := value.Decode(&raw); err != nil {
			return err
		}
		if raw.Launch != nil {
			a.Launch = *raw.Launch
		}
		a.Wait = time.Duration(raw.Wait)
		a.Shell = raw.Shell
		a.Prompt = raw.Prompt
		a.PromptLabel = raw.PromptLabel
		a.PromptChoices = raw.PromptChoices
		a.Tap = decodeTextNode(raw.Tap)
		a.Input = decodeTextNode(raw.Input)
		return nil
	default:
		return fmt.Errorf("invalid scenario action node kind %v", value.Kind)
	}
}

func decodeTextNode(n yaml.Node) string {
	if n.Kind == 0 {
		return ""
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value
	case yaml.MappingNode:
		var m struct {
			Text string `yaml:"text"`
		}
		if err := n.Decode(&m); err == nil {
			return m.Text
		}
	}
	return ""
}

// flexibleDuration accepts YAML numbers (ns) or strings like "10s".
type flexibleDuration time.Duration

func (d *flexibleDuration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	s := strings.TrimSpace(value.Value)
	if s == "" {
		*d = 0
		return nil
	}
	if parsed, err := time.ParseDuration(s); err == nil {
		*d = flexibleDuration(parsed)
		return nil
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		*d = flexibleDuration(time.Duration(n))
		return nil
	}
	return fmt.Errorf("invalid duration %q", s)
}

// Scenario is a named action list.
type Scenario struct {
	Name    string   `yaml:"name" json:"name"`
	Actions []Action `yaml:"actions" json:"actions"`
}

// Run executes scenarios; tap/input are best-effort and may no-op if UIAutomator unavailable.
func Run(ctx context.Context, client *adb.Client, serial string, target launcher.Target, list []Scenario, tl *timeline.Builder) error {
	if tl == nil {
		tl = timeline.New(time.Now().UTC())
	}
	if len(list) == 0 {
		list = []Scenario{{Name: "startup", Actions: []Action{{Launch: true}, {Wait: 10 * time.Second}}}}
	}
	for _, sc := range list {
		tl.Add("scenario", "start "+sc.Name, "RUNTIME_OBSERVATION")
		for _, a := range sc.Actions {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			switch {
			case a.Launch:
				if target.Package == "" {
					return fmt.Errorf("scenario %q: launch requires package", sc.Name)
				}
				if _, err := launcher.Launch(ctx, client, serial, target); err != nil {
					tl.Add("scenario", "launch failed: "+err.Error(), "RUNTIME_OBSERVATION")
					return fmt.Errorf("scenario %q launch: %w", sc.Name, err)
				}
				tl.Add("scenario", "launch ok ("+target.Component()+")", "RUNTIME_OBSERVATION")
			case a.Wait > 0:
				tl.Add("scenario", fmt.Sprintf("wait %s", a.Wait), "RUNTIME_OBSERVATION")
				t := time.NewTimer(a.Wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return ctx.Err()
				case <-t.C:
				}
			case a.Tap != "":
				// Best-effort: dump UI hierarchy and tap first matching text node.
				tl.Add("scenario", "tap text="+a.Tap, "RUNTIME_OBSERVATION")
				if err := tapText(ctx, client, serial, a.Tap); err != nil {
					tl.Add("scenario", "tap unresolved: "+err.Error(), "INFERENCE")
				}
			case a.Input != "":
				tl.Add("scenario", "input text", "RUNTIME_OBSERVATION")
				if err := TypeText(ctx, client, serial, a.Input); err != nil {
					tl.Add("scenario", "input failed: "+err.Error(), "INFERENCE")
				}
			case a.Shell != "":
				tl.Add("scenario", "shell:"+a.Shell, "RUNTIME_OBSERVATION")
				_, _ = client.Shell(ctx, serial, "sh", "-c", a.Shell)
			}
		}
		tl.Add("scenario", "end "+sc.Name, "RUNTIME_OBSERVATION")
	}
	return nil
}

// ClearFocusedField deletes characters from the focused EditText (portable; no `seq`).
func ClearFocusedField(ctx context.Context, client *adb.Client, serial string) {
	if client == nil || serial == "" {
		return
	}
	// KEYCODE_MOVE_END=123, KEYCODE_DEL=67 — avoid `seq` (missing on some images).
	_, _ = client.Shell(ctx, serial, "sh", "-c",
		`input keyevent 123; i=0; while [ "$i" -lt 32 ]; do input keyevent 67; i=$((i+1)); done`)
}

// TypeText types into the focused field. Digit-only / phone strings use keyevents
// so a leading zero (e.g. 0919…) is never dropped by `input text` / shell quirks.
func TypeText(ctx context.Context, client *adb.Client, serial, text string) error {
	if client == nil || serial == "" {
		return fmt.Errorf("adb client and serial required")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("empty input")
	}
	if isPhoneOrCode(text) {
		for _, r := range text {
			var code int
			switch {
			case r >= '0' && r <= '9':
				code = int(r-'0') + 7 // KEYCODE_0..9 = 7..16
			case r == '+':
				code = 81 // KEYCODE_PLUS
			default:
				continue
			}
			if _, err := client.Shell(ctx, serial, "input", "keyevent", strconv.Itoa(code)); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := client.Shell(ctx, serial, "input", "text", shellEscape(text))
	return err
}

func isPhoneOrCode(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '+' && i == 0 {
			continue
		}
		return false
	}
	// Prefer keyevents for numeric login fields (phone / OTP / PIN).
	return true
}

// UIHasDigits reports whether UI text contains want's digits in order
// (ignores spaces/dashes; accepts Persian/Arabic-Indic digits).
func UIHasDigits(xml, want string) bool {
	want = digitsOnly(want)
	if want == "" {
		return false
	}
	return strings.Contains(digitsOnly(xml), want)
}

// UIHasBlockingDialog reports in-app permission / notification overlays that
// must be dismissed before phone/OTP fields are usable (e.g. app notification overlays).
func UIHasBlockingDialog(xml string) bool {
	if xml == "" {
		return false
	}
	fold := foldUI(xml)
	switch {
	case strings.Contains(fold, "ارسال نوتیفیکیشن"),
		strings.Contains(strings.ToLower(xml), "allow notifications"),
		strings.Contains(fold, "نوتیفیکیشن") && (strings.Contains(fold, "اجازه میدهم") || strings.Contains(fold, "بعدا")),
		strings.Contains(xml, "POST_NOTIFICATIONS"):
		return true
	default:
		return false
	}
}

// UILooksLikeOTP reports the SMS code screen (not a permission dialog).
func UILooksLikeOTP(xml string) bool {
	if xml == "" || UIHasBlockingDialog(xml) {
		return false
	}
	fold := foldUI(xml)
	if strings.Contains(fold, "کد تأیید") || strings.Contains(fold, "کد تایید") ||
		strings.Contains(fold, "تایید شماره") || strings.Contains(fold, "تأیید شماره") ||
		strings.Contains(strings.ToLower(xml), "verification code") ||
		strings.Contains(strings.ToLower(xml), "enter code") {
		return true
	}
	// EditText with short code length while phone number is shown as label.
	if ExtractOTPFromUI(xml) != "" && (strings.Contains(fold, "موبایل") || strings.Contains(fold, "ورود")) {
		return true
	}
	return false
}

// UILooksLikePhone reports the phone-number login field screen.
func UILooksLikePhone(xml string) bool {
	if xml == "" || UIHasBlockingDialog(xml) {
		return false
	}
	fold := foldUI(xml)
	return strings.Contains(fold, "شماره موبایل") || strings.Contains(fold, "شمارهٔ موبایل") ||
		strings.Contains(strings.ToLower(xml), "phone number") ||
		strings.Contains(fold, "ورود با شماره")
}

// DismissBlockingDialogs taps common Allow / اجازه labels (best-effort).
func DismissBlockingDialogs(ctx context.Context, client *adb.Client, serial string) int {
	if client == nil || serial == "" {
		return 0
	}
	n := 0
	for _, label := range []string{
		"اجازه می‌دهم", "اجازه ميدهم", "اجازه میدهم", "اجازه دادن",
		"Allow", "ALLOW", "While using the app", "Allow notifications",
	} {
		if err := tapText(ctx, client, serial, label); err == nil {
			n++
			time.Sleep(400 * time.Millisecond)
		}
	}
	return n
}

// PrepareAuthUI dismisses permission overlays and waits until the phone or OTP
// screen is actually visible — prevents AuthGate OTP modal during نوتیفیکیشن.
// For phone, also navigates to the login screen when soft scenario taps missed.
func PrepareAuthUI(ctx context.Context, client *adb.Client, serial, kind string, timeout time.Duration) error {
	if client == nil || serial == "" {
		return fmt.Errorf("adb client and serial required")
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	deadline := time.Now().Add(timeout)
	navTick := 0
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		xml, err := DumpUI(ctx, client, serial)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if UIHasBlockingDialog(xml) {
			_ = DismissBlockingDialogs(ctx, client, serial)
			time.Sleep(600 * time.Millisecond)
			continue
		}
		switch kind {
		case "otp":
			if UILooksLikeOTP(xml) {
				return nil
			}
			// After phone submit the app may still show Allow — already handled above.
		case "phone":
			if UILooksLikePhone(xml) {
				return nil
			}
			// Self-heal navigation when prior soft taps missed (common under overlay race).
			navTick++
			if navTick%2 == 1 {
				_ = tapText(ctx, client, serial, "دیوار من")
				time.Sleep(700 * time.Millisecond)
			} else if strings.Contains(foldUI(xml), "ورود به حساب") {
				_ = tapText(ctx, client, serial, "ورود به حساب کاربری")
				time.Sleep(900 * time.Millisecond)
				_ = tapText(ctx, client, serial, "ورود با شماره موبایل")
				time.Sleep(700 * time.Millisecond)
			} else {
				_ = tapText(ctx, client, serial, "ورود به حساب کاربری")
				time.Sleep(700 * time.Millisecond)
				_ = tapText(ctx, client, serial, "ورود با شماره موبایل")
				time.Sleep(700 * time.Millisecond)
			}
		default:
			return nil
		}
		_ = DismissBlockingDialogs(ctx, client, serial)
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s screen (clear permission dialogs first)", kind)
}

// TapText taps a UI node by visible text (exported for Lab auth prep).
func TapText(ctx context.Context, client *adb.Client, serial, text string) error {
	return tapText(ctx, client, serial, text)
}

// ExtractOTPFromUI returns a 4–8 digit code from an EditText/password field,
// ignoring phone-length numbers (10–11+ digits) shown elsewhere on the screen.
func ExtractOTPFromUI(xml string) string {
	best := ""
	for i := 0; i < len(xml); {
		start := strings.Index(xml[i:], "<node ")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(xml[start:], ">")
		if end < 0 {
			break
		}
		end += start
		tag := xml[start:end]
		i = end + 1
		class := xmlAttr(tag, "class")
		text := xmlAttr(tag, "text")
		d := digitsOnly(text)
		if len(d) < 4 || len(d) > 8 {
			continue
		}
		score := 0
		switch {
		case strings.Contains(class, "EditText"):
			score = 3
		case xmlAttr(tag, "password") == "true":
			score = 3
		case xmlAttr(tag, "focused") == "true":
			score = 2
		default:
			score = 1
		}
		if score >= 2 || best == "" {
			best = d
			if score >= 3 {
				return best
			}
		}
	}
	return best
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= '۰' && r <= '۹': // Persian/Arabic-Indic digits
			b.WriteRune(rune('0' + (r - '۰')))
		case r >= '٠' && r <= '٩': // Arabic-Indic
			b.WriteRune(rune('0' + (r - '٠')))
		}
	}
	return b.String()
}

// DumpUI returns a uiautomator hierarchy dump.
func DumpUI(ctx context.Context, client *adb.Client, serial string) (string, error) {
	remote := "/data/local/tmp/apkcheck-ui.xml"
	if _, err := client.Shell(ctx, serial, "uiautomator", "dump", remote); err != nil {
		return "", err
	}
	return client.Shell(ctx, serial, "cat", remote)
}

// FocusEditText taps the most likely phone/OTP input (EditText or Compose field).
func FocusEditText(ctx context.Context, client *adb.Client, serial string) error {
	xml, err := DumpUI(ctx, client, serial)
	if err != nil {
		return err
	}
	type hit struct{ x, y, score int }
	var best *hit
	for i := 0; i < len(xml); {
		start := strings.Index(xml[i:], "<node ")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(xml[start:], ">")
		if end < 0 {
			break
		}
		end += start
		tag := xml[start:end]
		i = end + 1
		class := xmlAttr(tag, "class")
		text := xmlAttr(tag, "text")
		desc := xmlAttr(tag, "content-desc")
		bounds := xmlAttr(tag, "bounds")
		if bounds == "" {
			continue
		}
		var x1, y1, x2, y2 int
		if _, err := fmt.Sscanf(bounds, "[%d,%d][%d,%d]", &x1, &y1, &x2, &y2); err != nil {
			continue
		}
		h := y2 - y1
		w := x2 - x1
		score := 0
		switch {
		case strings.Contains(class, "EditText"):
			score = 12
		case xmlAttr(tag, "password") == "true":
			score = 11
		case strings.Contains(foldUI(text), "شماره") && h < 80 && w > 100:
			// Field hint / label row near the input — tap slightly below center.
			score = 8
			y1, y2 = y2, y2+40
		case xmlAttr(tag, "focusable") == "true" && xmlAttr(tag, "clickable") == "true" &&
			text == "" && desc == "" && h >= 40 && h <= 120 && w > 120:
			// Empty Compose input chrome.
			score = 7
		default:
			continue
		}
		if xmlAttr(tag, "focused") == "true" {
			score += 3
		}
		cx, cy := (x1+x2)/2, (y1+y2)/2
		if best == nil || score > best.score || (score == best.score && cy > best.y) {
			best = &hit{cx, cy, score}
		}
	}
	if best == nil {
		// Last resort: upper-mid screen where phone fields usually sit.
		_, _ = client.Shell(ctx, serial, "input", "tap", "160", "280")
		return nil
	}
	_, err = client.Shell(ctx, serial, "input", "tap", strconv.Itoa(best.x), strconv.Itoa(best.y))
	return err
}

func tapText(ctx context.Context, client *adb.Client, serial, text string) error {
	remote := "/data/local/tmp/apkcheck-ui.xml"
	if _, err := client.Shell(ctx, serial, "uiautomator", "dump", remote); err != nil {
		return fmt.Errorf("uiautomator dump: %w", err)
	}
	xml, err := client.Shell(ctx, serial, "cat", remote)
	if err != nil {
		return err
	}
	x, y, ok := findTextBoundsCenter(xml, text)
	if !ok {
		return fmt.Errorf("no UI node with text %q", text)
	}
	_, err = client.Shell(ctx, serial, "input", "tap", fmt.Sprintf("%d", x), fmt.Sprintf("%d", y))
	return err
}

// findTextBoundsCenter parses uiautomator dump XML for a matching node.
// Prefers clickable targets. When the label is a non-clickable child (common in
// Compose), remaps to the smallest clickable node covering that point — and
// prefers candidates that have such a cover (e.g. login CTA vs page title).
func findTextBoundsCenter(xml, want string) (x, y int, ok bool) {
	want = strings.TrimSpace(want)
	if want == "" {
		return 0, 0, false
	}
	wantFold := foldUI(want)
	wantLower := strings.ToLower(want)

	type cand struct {
		x, y, score, yBias, textLen int
		covered                     bool
	}
	var best *cand

	for i := 0; i < len(xml); {
		start := strings.Index(xml[i:], "<node ")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(xml[start:], ">")
		if end < 0 {
			break
		}
		end += start
		tag := xml[start:end]
		i = end + 1

		text := xmlAttr(tag, "text")
		desc := xmlAttr(tag, "content-desc")
		bounds := xmlAttr(tag, "bounds")
		clickable := xmlAttr(tag, "clickable") == "true"
		if bounds == "" {
			continue
		}
		var x1, y1, x2, y2 int
		if _, err := fmt.Sscanf(bounds, "[%d,%d][%d,%d]", &x1, &y1, &x2, &y2); err != nil {
			continue
		}
		cx, cy := (x1+x2)/2, (y1+y2)/2
		score := 0
		switch {
		case text == want || desc == want:
			score = 8
		case foldUI(text) == wantFold || foldUI(desc) == wantFold:
			score = 7
		case text != "" && (strings.Contains(text, want) || strings.Contains(foldUI(text), wantFold) ||
			strings.Contains(strings.ToLower(text), wantLower)):
			// Prefer short labels (button) over long instructional copy that mentions the label.
			if len([]rune(text)) > len([]rune(want))+12 {
				score = 2
			} else {
				score = 4
			}
		case desc != "" && (strings.Contains(desc, want) || strings.Contains(foldUI(desc), wantFold) ||
			strings.Contains(strings.ToLower(desc), wantLower)):
			score = 3
		}
		if score == 0 {
			continue
		}
		tx, ty := cx, cy
		covered := clickable
		if !clickable {
			if ax, ay, ok2 := clickableCovering(xml, cx, cy); ok2 {
				tx, ty = ax, ay
				covered = true
				score += 3
			}
		} else {
			score += 2
		}
		labelLen := len([]rune(text))
		if labelLen == 0 {
			labelLen = len([]rune(desc))
		}
		c := &cand{x: tx, y: ty, score: score, yBias: ty, covered: covered, textLen: labelLen}
		if best == nil ||
			c.score > best.score ||
			(c.score == best.score && c.covered && !best.covered) ||
			(c.score == best.score && c.covered == best.covered && c.textLen > 0 && (best.textLen == 0 || c.textLen < best.textLen)) ||
			(c.score == best.score && c.covered == best.covered && c.textLen == best.textLen && c.yBias > best.yBias) {
			best = c
		}
	}
	if best == nil {
		return 0, 0, false
	}
	return best.x, best.y, true
}

// foldUI strips ZWNJ / Arabic combining marks so "شماره موبایل" matches "شمارهٔ موبایل".
func foldUI(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\u200c' || r == '\u200d' || r == '\u200e' || r == '\u200f':
			continue
		case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r):
			continue
		case r == 'ي' || r == 'ی':
			b.WriteRune('ی')
		case r == 'ك' || r == 'ک':
			b.WriteRune('ک')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func clickableCovering(xml string, x, y int) (cx, cy int, ok bool) {
	type box struct{ x1, y1, x2, y2, area int }
	var best *box
	for i := 0; i < len(xml); {
		start := strings.Index(xml[i:], "<node ")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(xml[start:], ">")
		if end < 0 {
			break
		}
		end += start
		tag := xml[start:end]
		i = end + 1
		if xmlAttr(tag, "clickable") != "true" {
			continue
		}
		bounds := xmlAttr(tag, "bounds")
		var x1, y1, x2, y2 int
		if _, err := fmt.Sscanf(bounds, "[%d,%d][%d,%d]", &x1, &y1, &x2, &y2); err != nil {
			continue
		}
		if x < x1 || x > x2 || y < y1 || y > y2 {
			continue
		}
		area := (x2 - x1) * (y2 - y1)
		if area <= 0 {
			continue
		}
		// Prefer smallest covering clickable (avoid full-screen roots).
		if best == nil || area < best.area {
			best = &box{x1, y1, x2, y2, area}
		}
	}
	if best == nil {
		return 0, 0, false
	}
	return (best.x1 + best.x2) / 2, (best.y1 + best.y2) / 2, true
}

func xmlAttr(tag, name string) string {
	key := name + `="`
	idx := strings.Index(tag, key)
	if idx < 0 {
		return ""
	}
	v := tag[idx+len(key):]
	end := strings.IndexByte(v, '"')
	if end < 0 {
		return ""
	}
	return v[:end]
}

func shellEscape(s string) string {
	// adb `input text` encodes space as %s; drop shell-metacharacters.
	// Note: digit-only phone/OTP should use TypeText keyevents instead — leading
	// zeros are unreliable via `input text` on some API levels / shells.
	var b strings.Builder
	for _, ch := range s {
		switch ch {
		case ' ':
			b.WriteString("%s")
		case '\t':
			b.WriteString("%s")
		case '\n', '\r', '\'', '"', '\\', ';', '&', '|', '<', '>', '$', '`':
			// skip unsafe
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}
