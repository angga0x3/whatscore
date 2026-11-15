package contacts

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestUpsertReportsChange(t *testing.T) {
	cache := New()
	base := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		input   Contact
		want    bool
		wantLen int
	}{
		{
			name:    "new contact",
			input:   Contact{JID: "628111@s.whatsapp.net", Name: "Ana", UpdatedAt: base},
			want:    true,
			wantLen: 1,
		},
		{
			name:    "identical repeat is not a change",
			input:   Contact{JID: "628111@s.whatsapp.net", Name: "Ana", UpdatedAt: base.Add(time.Minute)},
			want:    false,
			wantLen: 1,
		},
		{
			name:    "name change",
			input:   Contact{JID: "628111@s.whatsapp.net", Name: "Ana Maria", UpdatedAt: base},
			want:    true,
			wantLen: 1,
		},
		{
			name:    "push name change",
			input:   Contact{JID: "628111@s.whatsapp.net", Name: "Ana Maria", PushName: "ana", UpdatedAt: base},
			want:    true,
			wantLen: 1,
		},
		{
			name:    "same push name is not a change",
			input:   Contact{JID: "628111@s.whatsapp.net", Name: "Ana Maria", PushName: "ana", UpdatedAt: base.Add(2 * time.Minute)},
			want:    false,
			wantLen: 1,
		},
		{
			name:    "second contact",
			input:   Contact{JID: "628222@s.whatsapp.net", Name: "Budi"},
			want:    true,
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed, err := cache.Upsert(tt.input)
			if err != nil {
				t.Fatalf("upsert: %v", err)
			}
			if changed != tt.want {
				t.Fatalf("changed = %t, want %t", changed, tt.want)
			}
			if got := cache.Len(); got != tt.wantLen {
				t.Fatalf("len = %d, want %d", got, tt.wantLen)
			}
		})
	}

	got, ok := cache.Get("628111@s.whatsapp.net")
	if !ok {
		t.Fatal("contact missing after upserts")
	}
	if got.Name != "Ana Maria" || got.PushName != "ana" {
		t.Fatalf("contact = %+v, want last write", got)
	}
	if !got.UpdatedAt.Equal(base.Add(2 * time.Minute)) {
		t.Fatalf("UpdatedAt = %v, want the last write's timestamp", got.UpdatedAt)
	}
}

func TestUpsertRejectsInvalidJID(t *testing.T) {
	tests := []struct {
		name string
		jid  string
	}{
		{name: "empty", jid: ""},
		{name: "spaces", jid: "   "},
		{name: "tab", jid: "\t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := New()
			changed, err := cache.Upsert(Contact{JID: tt.jid, Name: "x"})
			if !errors.Is(err, ErrInvalidContact) {
				t.Fatalf("err = %v, want ErrInvalidContact", err)
			}
			if changed {
				t.Fatal("invalid input must not report a change")
			}
			if got := cache.Len(); got != 0 {
				t.Fatalf("len = %d, want 0", got)
			}
		})
	}
}

func TestGetAndDelete(t *testing.T) {
	cache := New()
	want := Contact{JID: "628333@s.whatsapp.net", Name: "Citra", PushName: "citra"}
	if _, err := cache.Upsert(want); err != nil {
		t.Fatal(err)
	}

	got, ok := cache.Get(want.JID)
	if !ok || got != want {
		t.Fatalf("Get = %+v, %t; want %+v, true", got, ok, want)
	}
	if _, ok := cache.Get("628999@s.whatsapp.net"); ok {
		t.Fatal("unknown jid reported as cached")
	}

	cache.Delete(want.JID)
	if _, ok := cache.Get(want.JID); ok {
		t.Fatal("contact still cached after delete")
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("len = %d, want 0", got)
	}

	cache.Delete(want.JID) // unknown delete is a no-op
	if got := cache.Len(); got != 0 {
		t.Fatalf("len after repeated delete = %d, want 0", got)
	}
}

func TestListSortedByJID(t *testing.T) {
	cache := New()
	// Insertion order is deliberately not sorted.
	for _, jid := range []string{
		"628300@s.whatsapp.net",
		"628100@s.whatsapp.net",
		"628200@s.whatsapp.net",
	} {
		if _, err := cache.Upsert(Contact{JID: jid}); err != nil {
			t.Fatal(err)
		}
	}

	want := []string{
		"628100@s.whatsapp.net",
		"628200@s.whatsapp.net",
		"628300@s.whatsapp.net",
	}
	for round := 0; round < 3; round++ {
		got := cache.List()
		if len(got) != len(want) {
			t.Fatalf("round %d: len = %d, want %d", round, len(got), len(want))
		}
		for i, contact := range got {
			if contact.JID != want[i] {
				t.Fatalf("round %d: List[%d] = %q, want %q", round, i, contact.JID, want[i])
			}
		}
	}
}

func TestListReturnsOwnedSlice(t *testing.T) {
	cache := New()
	if _, err := cache.Upsert(Contact{JID: "628444@s.whatsapp.net", Name: "Dewi"}); err != nil {
		t.Fatal(err)
	}

	list := cache.List()
	list[0].Name = "mutated"

	got, ok := cache.Get("628444@s.whatsapp.net")
	if !ok || got.Name != "Dewi" {
		t.Fatalf("cache observed caller mutation: %+v", got)
	}
}

func TestConcurrentAccess(t *testing.T) {
	cache := New()

	const (
		writers = 8
		readers = 8
		perGoro = 64
	)

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perGoro; j++ {
				jid := fmt.Sprintf("628%05d@s.whatsapp.net", i*perGoro+j)
				if _, err := cache.Upsert(Contact{JID: jid, Name: "n"}); err != nil {
					t.Errorf("upsert %s: %v", jid, err)
					return
				}
				if j%7 == 0 {
					cache.Delete(jid)
				}
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoro; j++ {
				cache.Get("62800000@s.whatsapp.net")
				cache.List()
				cache.Len()
			}
		}()
	}
	wg.Wait()

	if got := cache.Len(); got != len(cache.List()) {
		t.Fatalf("len = %d, list = %d", got, len(cache.List()))
	}
}
