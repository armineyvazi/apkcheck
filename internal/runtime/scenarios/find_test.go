package scenarios

import "testing"

func TestFindTextBoundsCenterExactAndContains(t *testing.T) {
	xml := `<hierarchy>
<node text="جستجو در همهٔ آگهی‌ها" content-desc="" bounds="[100,200][500,280]" />
<node text="۳۵۰,۰۰۰,۰۰۰ تومان" content-desc="" bounds="[50,800][900,900]" />
<node text="" content-desc="اطلاعات تماس" bounds="[200,1800][800,1900]" />
</hierarchy>`

	x, y, ok := findTextBoundsCenter(xml, "جستجو در همهٔ آگهی‌ها")
	if !ok || x != 300 || y != 240 {
		t.Fatalf("exact text: ok=%v x=%d y=%d", ok, x, y)
	}
	x, y, ok = findTextBoundsCenter(xml, "جستجو در همه")
	if !ok || x != 300 {
		t.Fatalf("contains text: ok=%v x=%d y=%d", ok, x, y)
	}
	x, y, ok = findTextBoundsCenter(xml, "تومان")
	if !ok || y != 850 {
		t.Fatalf("price contains: ok=%v x=%d y=%d", ok, x, y)
	}
	x, y, ok = findTextBoundsCenter(xml, "اطلاعات تماس")
	if !ok || y != 1850 {
		t.Fatalf("content-desc: ok=%v x=%d y=%d", ok, x, y)
	}
	if _, _, ok = findTextBoundsCenter(xml, "nope"); ok {
		t.Fatal("expected miss")
	}
}
