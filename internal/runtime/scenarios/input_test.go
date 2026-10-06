package scenarios

import "testing"

func TestIsPhoneOrCode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"09192500072", true},
		{"+989192500072", true},
		{"123456", true},
		{"", false},
		{"09ab", false},
		{"hello", false},
	}
	for _, c := range cases {
		if got := isPhoneOrCode(c.in); got != c.want {
			t.Fatalf("%q: got %v want %v", c.in, got, c.want)
		}
	}
}

func TestShellEscapeKeepsLeadingZero(t *testing.T) {
	got := shellEscape("09192500072")
	if got != "09192500072" {
		t.Fatalf("got %q", got)
	}
}

func TestUIHasDigits(t *testing.T) {
	xml := `<node text="09 19 250 0072" class="android.widget.EditText" bounds="[0,0][100,100]" />`
	if !UIHasDigits(xml, "09192500072") {
		t.Fatal("expected match with spaced UI digits")
	}
	if UIHasDigits(xml, "09190000000") {
		t.Fatal("should not match wrong number")
	}
	// Wrong number that was typed historically (missing/extra digit)
	if UIHasDigits(`text="9192500072"`, "09192500072") {
		t.Fatal("leading-zero loss must be detected")
	}
	if !UIHasDigits(`text="9192500072"`, "9192500072") {
		t.Fatal("10-digit form should match")
	}
	// apps may show Persian digits
	if !UIHasDigits(`text="۰۹۱۹ ۲۵۰ ۰۰۷۲"`, "09192500072") {
		t.Fatal("Persian digits should match Latin phone")
	}
}

func TestDigitsOnly(t *testing.T) {
	if digitsOnly("+98 919 250 0072") != "989192500072" {
		t.Fatal(digitsOnly("+98 919 250 0072"))
	}
}

func TestExtractOTPFromUI(t *testing.T) {
	xml := `<hierarchy>
<node text="۰۹۱۹ ۲۵۰ ۰۰۷۲" class="android.widget.TextView" bounds="[0,0][100,40]" />
<node text="182480" class="android.widget.EditText" bounds="[16,100][300,140]" />
<node text="ورود" clickable="false" bounds="[146,395][175,420]" />
</hierarchy>`
	if got := ExtractOTPFromUI(xml); got != "182480" {
		t.Fatalf("got %q", got)
	}
	// Phone-only screen must not invent an OTP
	if got := ExtractOTPFromUI(`<node text="09192500072" class="android.widget.EditText" />`); got != "" {
		t.Fatalf("phone must not count as OTP: %q", got)
	}
}

func TestUIBlockingDialogVsOTP(t *testing.T) {
	notif := `<hierarchy>
<node text="ارسال نوتیفیکیشن" />
<node text="برای دریافت و نمایش نوتیفیکیشن، ابتدا دکمهٔ «اجازه می‌دهم» و بعد، دکمهٔ Allow را بزنید." />
<node text="بعداً" />
<node text="اجازه می‌دهم" />
</hierarchy>`
	if !UIHasBlockingDialog(notif) {
		t.Fatal("notif dialog should block")
	}
	if UILooksLikeOTP(notif) {
		t.Fatal("notif must not look like OTP")
	}
	otp := `<hierarchy>
<node text="کد تأیید به شمارهٔ بالا فرستاده شد." />
<node text="182480" class="android.widget.EditText" />
<node text="ورود" />
</hierarchy>`
	if UIHasBlockingDialog(otp) {
		t.Fatal("otp screen is not a blocking dialog")
	}
	if !UILooksLikeOTP(otp) {
		t.Fatal("expected OTP screen")
	}
}

func TestFoldUIMatchesHamzaYe(t *testing.T) {
	// apps may use "شمارهٔ موبایل" (with Arabic hamza) vs scenario "شماره موبایل"
	if foldUI("شمارهٔ موبایل") != foldUI("شماره موبایل") {
		t.Fatalf("%q vs %q", foldUI("شمارهٔ موبایل"), foldUI("شماره موبایل"))
	}
	if foldUI("اجازه می‌دهم") == "" {
		t.Fatal("empty fold")
	}
}

func TestFindPrefersClickableCoveringLoginLabel(t *testing.T) {
	// Title (no cover) + button label (covered by clickable View) — must pick button.
	xml := `<hierarchy>
<node text="ورود به حساب کاربری" clickable="false" bounds="[16,104][304,132]" />
<node text="ورود به حساب کاربری" clickable="false" bounds="[56,234][248,259]" />
<node text="" clickable="true" class="android.view.View" bounds="[16,218][304,274]" />
</hierarchy>`
	x, y, ok := findTextBoundsCenter(xml, "ورود به حساب کاربری")
	if !ok {
		t.Fatal("miss")
	}
	if x != 160 || y != 246 {
		t.Fatalf("want clickable button center 160,246 got %d,%d", x, y)
	}
}
