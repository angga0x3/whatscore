package groups

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestUpsertNormalizesParticipants(t *testing.T) {
	base := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		input        Group
		want         []string
		wantLenAfter int
	}{
		{
			name: "sorted ascending",
			input: Group{ID: "1203630@g.us", Participants: []string{
				"628300@s.whatsapp.net",
				"628100@s.whatsapp.net",
				"628200@s.whatsapp.net",
			}},
			want:         []string{"628100@s.whatsapp.net", "628200@s.whatsapp.net", "628300@s.whatsapp.net"},
			wantLenAfter: 1,
		},
		{
			name: "duplicates collapsed",
			input: Group{ID: "1203631@g.us", Participants: []string{
				"628200@s.whatsapp.net",
				"628100@s.whatsapp.net",
				"628200@s.whatsapp.net",
				"628100@s.whatsapp.net",
			}},
			want:         []string{"628100@s.whatsapp.net", "628200@s.whatsapp.net"},
			wantLenAfter: 2,
		},
		{
			name:         "no participants",
			input:        Group{ID: "1203632@g.us", Subject: "empty", UpdatedAt: base},
			want:         []string{},
			wantLenAfter: 3,
		},
	}

	cache := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cache.Upsert(tt.input); err != nil {
				t.Fatalf("upsert: %v", err)
			}

			got, ok := cache.Get(tt.input.ID)
			if !ok {
				t.Fatalf("group %q missing after upsert", tt.input.ID)
			}
			if !reflect.DeepEqual(got.Participants, tt.want) {
				t.Fatalf("participants = %v, want %v", got.Participants, tt.want)
			}
			if got.Subject != tt.input.Subject {
				t.Fatalf("subject = %q, want %q", got.Subject, tt.input.Subject)
			}
			if gotLen := cache.Len(); gotLen != tt.wantLenAfter {
				t.Fatalf("len = %d, want %d", gotLen, tt.wantLenAfter)
			}
		})
	}
}

func TestUpsertRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input Group
	}{
		{name: "empty id", input: Group{}},
		{name: "blank id", input: Group{ID: "  "}},
		{
			name:  "empty participant",
			input: Group{ID: "1203630@g.us", Participants: []string{"628100@s.whatsapp.net", ""}},
		},
		{
			name:  "blank participant",
			input: Group{ID: "1203630@g.us", Participants: []string{"\t"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := New()
			if err := cache.Upsert(tt.input); !errors.Is(err, ErrInvalidGroup) {
				t.Fatalf("err = %v, want ErrInvalidGroup", err)
			}
			if got := cache.Len(); got != 0 {
				t.Fatalf("len = %d, want 0", got)
			}
		})
	}

	// A rejected update must leave an existing entry untouched.
	cache := New()
	good := Group{ID: "1203630@g.us", Subject: "kept", Participants: []string{"628100@s.whatsapp.net"}}
	if err := cache.Upsert(good); err != nil {
		t.Fatal(err)
	}
	if err := cache.Upsert(Group{ID: good.ID, Participants: []string{""}}); !errors.Is(err, ErrInvalidGroup) {
		t.Fatalf("err = %v, want ErrInvalidGroup", err)
	}
	got, ok := cache.Get(good.ID)
	if !ok || got.Subject != "kept" || len(got.Participants) != 1 {
		t.Fatalf("rejected upsert mutated cache: %+v", got)
	}
}

func TestUpsertReplacesParticipants(t *testing.T) {
	cache := New()
	if err := cache.Upsert(Group{ID: "1203630@g.us", Participants: []string{"628100@s.whatsapp.net", "628200@s.whatsapp.net"}}); err != nil {
		t.Fatal(err)
	}
	if err := cache.Upsert(Group{ID: "1203630@g.us", Subject: "renamed", Participants: []string{"628200@s.whatsapp.net"}}); err != nil {
		t.Fatal(err)
	}

	got, ok := cache.Get("1203630@g.us")
	if !ok {
		t.Fatal("group missing")
	}
	if want := []string{"628200@s.whatsapp.net"}; !reflect.DeepEqual(got.Participants, want) {
		t.Fatalf("participants = %v, want %v", got.Participants, want)
	}
	if got.Subject != "renamed" {
		t.Fatalf("subject = %q, want renamed", got.Subject)
	}
	if gotLen := cache.Len(); gotLen != 1 {
		t.Fatalf("len = %d, want 1", gotLen)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	cache := New()
	if err := cache.Upsert(Group{ID: "1203630@g.us", Participants: []string{"628100@s.whatsapp.net"}}); err != nil {
		t.Fatal(err)
	}

	got, ok := cache.Get("1203630@g.us")
	if !ok {
		t.Fatal("group missing")
	}
	got.Participants[0] = "mutated"

	again, _ := cache.Get("1203630@g.us")
	if again.Participants[0] != "628100@s.whatsapp.net" {
		t.Fatalf("cache observed caller mutation: %v", again.Participants)
	}
}

func TestGetUnknownAndDelete(t *testing.T) {
	cache := New()
	if _, ok := cache.Get("1203639@g.us"); ok {
		t.Fatal("unknown group reported as cached")
	}

	if err := cache.Upsert(Group{ID: "1203630@g.us"}); err != nil {
		t.Fatal(err)
	}
	cache.Delete("1203630@g.us")
	if _, ok := cache.Get("1203630@g.us"); ok {
		t.Fatal("group still cached after delete")
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("len = %d, want 0", got)
	}

	cache.Delete("1203630@g.us") // unknown delete is a no-op
	if got := cache.Len(); got != 0 {
		t.Fatalf("len after repeated delete = %d, want 0", got)
	}
}

func TestListSortedByID(t *testing.T) {
	cache := New()
	for _, id := range []string{"1203632@g.us", "1203630@g.us", "1203631@g.us"} {
		if err := cache.Upsert(Group{ID: id, Participants: []string{"628100@s.whatsapp.net"}}); err != nil {
			t.Fatal(err)
		}
	}

	want := []string{"1203630@g.us", "1203631@g.us", "1203632@g.us"}
	for round := 0; round < 3; round++ {
		got := cache.List()
		if len(got) != len(want) {
			t.Fatalf("round %d: len = %d, want %d", round, len(got), len(want))
		}
		for i, group := range got {
			if group.ID != want[i] {
				t.Fatalf("round %d: List[%d] = %q, want %q", round, i, group.ID, want[i])
			}
		}
	}

	list := cache.List()
	list[0].Participants[0] = "mutated"
	again, _ := cache.Get("1203630@g.us")
	if again.Participants[0] != "628100@s.whatsapp.net" {
		t.Fatalf("cache observed caller mutation through List: %v", again.Participants)
	}
}

func TestApplyParticipantChange(t *testing.T) {
	tests := []struct {
		name        string
		before      []string
		after       []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "no change",
			before:      []string{"a", "b"},
			after:       []string{"a", "b"},
			wantAdded:   nil,
			wantRemoved: nil,
		},
		{
			name:        "added only",
			before:      []string{"a"},
			after:       []string{"a", "b", "c"},
			wantAdded:   []string{"b", "c"},
			wantRemoved: nil,
		},
		{
			name:        "removed only",
			before:      []string{"a", "b", "c"},
			after:       []string{"a"},
			wantAdded:   nil,
			wantRemoved: []string{"b", "c"},
		},
		{
			name:        "added and removed",
			before:      []string{"b", "d"},
			after:       []string{"a", "b"},
			wantAdded:   []string{"a"},
			wantRemoved: []string{"d"},
		},
		{
			name:        "input order does not matter",
			before:      []string{"c", "a", "b"},
			after:       []string{"b", "c", "a"},
			wantAdded:   nil,
			wantRemoved: nil,
		},
		{
			name:        "duplicates ignored",
			before:      []string{"a", "a"},
			after:       []string{"a", "b", "b"},
			wantAdded:   []string{"b"},
			wantRemoved: nil,
		},
		{
			name:        "blank entries ignored",
			before:      []string{"a", ""},
			after:       []string{"a", " ", "b"},
			wantAdded:   []string{"b"},
			wantRemoved: nil,
		},
		{
			name:        "empty before",
			before:      nil,
			after:       []string{"b", "a"},
			wantAdded:   []string{"a", "b"},
			wantRemoved: nil,
		},
		{
			name:        "empty after",
			before:      []string{"b", "a"},
			after:       nil,
			wantAdded:   nil,
			wantRemoved: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := applyParticipantChange(tt.before, tt.after)
			if !reflect.DeepEqual(added, tt.wantAdded) {
				t.Errorf("added = %v, want %v", added, tt.wantAdded)
			}
			if !reflect.DeepEqual(removed, tt.wantRemoved) {
				t.Errorf("removed = %v, want %v", removed, tt.wantRemoved)
			}
		})
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
				id := "120363" + string(rune('0'+i)) + "@g.us"
				group := Group{
					ID:           id,
					Subject:      "subject",
					Participants: []string{"628100@s.whatsapp.net", "628200@s.whatsapp.net"},
				}
				if err := cache.Upsert(group); err != nil {
					t.Errorf("upsert %s: %v", id, err)
					return
				}
				if j%5 == 0 {
					if got, ok := cache.Get(id); ok {
						applyParticipantChange(nil, got.Participants)
					}
				}
				if j%11 == 0 {
					cache.Delete(id)
				}
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoro; j++ {
				cache.Get("1203630@g.us")
				cache.List()
				cache.Len()
			}
		}()
	}
	wg.Wait()

	if got := cache.Len(); got != len(cache.List()) {
		t.Fatalf("len = %d, list = %d", got, len(cache.List()))
	}
	for _, group := range cache.List() {
		if !isSortedUnique(group.Participants) {
			t.Fatalf("group %s participants not sorted/unique: %v", group.ID, group.Participants)
		}
	}
}

// isSortedUnique checks the invariant Upsert guarantees.
func isSortedUnique(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}
