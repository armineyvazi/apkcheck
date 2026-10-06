package authgate_test

import (
	"context"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/events"
)

func TestPrefillWait(t *testing.T) {
	root := t.TempDir()
	m := authgate.New(root, events.NewBus(8))
	m.Prefill("run-1", authgate.KindPhone, "+98 912 345 6789")
	v, err := m.Wait(context.Background(), "run-1", authgate.KindPhone, "", "com.example.app", time.Second)
	if err != nil || v != "+989123456789" {
		t.Fatalf("got %q %v", v, err)
	}
}

func TestSubmitUnblocksWaitAcrossManagers(t *testing.T) {
	root := t.TempDir()
	waiter := authgate.New(root, events.NewBus(8))
	submitter := authgate.New(root, nil) // simulate MCP/UI other process

	done := make(chan string, 1)
	go func() {
		v, err := waiter.Wait(context.Background(), "run-2", authgate.KindOTP, "SMS", "com.example.app", 3*time.Second)
		if err != nil {
			done <- "err:" + err.Error()
			return
		}
		done <- v
	}()
	time.Sleep(80 * time.Millisecond)
	pending := waiter.PendingFor("run-2")
	if len(pending) != 1 || pending[0].Kind != authgate.KindOTP {
		t.Fatalf("pending=%#v", pending)
	}
	if _, err := submitter.Submit("run-2", authgate.KindOTP, "123456"); err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-done:
		if v != "123456" {
			t.Fatalf("got %s", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSubmitBeforeWaitPrefill(t *testing.T) {
	root := t.TempDir()
	m := authgate.New(root, nil)
	if _, err := m.Submit("run-3", "phone", "09121234567"); err != nil {
		t.Fatal(err)
	}
	v, err := m.Wait(context.Background(), "run-3", "mobile", "", "com.example", time.Second)
	if err != nil || v != "09121234567" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestNormalizeKind(t *testing.T) {
	if authgate.NormalizeKind("sms_code") != authgate.KindOTP {
		t.Fatal("otp alias")
	}
	if authgate.NormalizeKind("tel") != authgate.KindPhone {
		t.Fatal("phone alias")
	}
	if authgate.NormalizeKind("notification") != authgate.KindChoice {
		t.Fatal("choice alias")
	}
	if !authgate.IsChoice("permission") {
		t.Fatal("IsChoice")
	}
}

func TestPhonePrefillKeepsLeadingZero(t *testing.T) {
	root := t.TempDir()
	m := authgate.New(root, nil)
	const phone = "09192500072"
	m.Prefill("run-phone", authgate.KindPhone, phone)
	v, err := m.Wait(context.Background(), "run-phone", authgate.KindPhone, "Phone", "com.example.app", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if v != phone {
		t.Fatalf("leading zero lost: got %q want %q", v, phone)
	}
	// Spaces / dashes stripped, digits preserved
	m.Prefill("run-phone-2", authgate.KindPhone, "0919-250-0072")
	v2, err := m.Wait(context.Background(), "run-phone-2", authgate.KindPhone, "", "com.example.app", time.Second)
	if err != nil || v2 != phone {
		t.Fatalf("got %q %v", v2, err)
	}
}
