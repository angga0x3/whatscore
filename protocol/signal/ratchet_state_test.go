package signal

import (
	"errors"
	"testing"
)

type conversation struct {
	alice *State
	bob   *State
}

func newConversation(tb testing.TB) conversation {
	tb.Helper()
	_, alice := signingKey(tb)
	_, bob := signingKey(tb)
	bobSigned := fixedKey(tb, 0x21)
	bundle := PreKeyBundle{
		IdentityKey:           bob.Public,
		SignedPreKeyID:        7,
		SignedPreKey:          bobSigned.Public,
		SignedPreKeySignature: signPreKey(tb, bob, bobSigned.Public),
	}
	init, err := Initiate(alice, bundle)
	if err != nil {
		tb.Fatalf("Initiate: %v", err)
	}
	responder, err := Respond(bob, bobSigned, nil, alice.Public, init.EphemeralPublic)
	if err != nil {
		tb.Fatalf("Respond: %v", err)
	}
	aliceState, err := NewInitiator(init.Keys.RootKey, bobSigned.Public, init.Keys.ChainKey)
	if err != nil {
		tb.Fatalf("NewInitiator: %v", err)
	}
	return conversation{alice: aliceState, bob: NewResponder(responder.RootKey, bobSigned, responder.ChainKey)}
}

func TestRatchetConversation(t *testing.T) {
	c := newConversation(t)

	for round := 0; round < 3; round++ {
		header, aliceKeys, err := c.alice.NextOutbound()
		if err != nil {
			t.Fatal(err)
		}
		bobKeys, err := c.bob.Receive(header)
		if err != nil {
			t.Fatalf("bob receive round %d: %v", round, err)
		}
		if aliceKeys != bobKeys {
			t.Fatalf("round %d keys differ", round)
		}

		header, bobKeys, err = c.bob.NextOutbound()
		if err != nil {
			t.Fatal(err)
		}
		aliceKeys, err = c.alice.Receive(header)
		if err != nil {
			t.Fatalf("alice receive round %d: %v", round, err)
		}
		if aliceKeys != bobKeys {
			t.Fatalf("round %d reply keys differ", round)
		}
	}
}

func TestRatchetOutOfOrder(t *testing.T) {
	c := newConversation(t)
	var headers []Header
	var keys []MessageKeys
	for i := 0; i < 3; i++ {
		header, messageKeys, err := c.alice.NextOutbound()
		if err != nil {
			t.Fatal(err)
		}
		headers = append(headers, header)
		keys = append(keys, messageKeys)
	}

	got, err := c.bob.Receive(headers[2])
	if err != nil {
		t.Fatalf("receive #2: %v", err)
	}
	if got != keys[2] {
		t.Fatal("message 2 keys differ")
	}
	for _, index := range []int{0, 1} {
		got, err := c.bob.Receive(headers[index])
		if err != nil {
			t.Fatalf("receive #%d: %v", index, err)
		}
		if got != keys[index] {
			t.Fatalf("message %d keys differ", index)
		}
	}
	if _, err := c.bob.Receive(headers[0]); !errors.Is(err, ErrOldMessage) {
		t.Fatalf("duplicate: want ErrOldMessage, got %v", err)
	}
}

func TestRatchetRejectsFarFuture(t *testing.T) {
	c := newConversation(t)
	header, _, err := c.alice.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	header.MessageNumber = MaxFutureMessages + 1
	if _, err := c.bob.Receive(header); !errors.Is(err, ErrTooFarInFuture) {
		t.Fatalf("want ErrTooFarInFuture, got %v", err)
	}
}

func TestRatchetSkippedKeyLimit(t *testing.T) {
	c := newConversation(t)
	header, _, err := c.alice.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	// The receiver chain is unknown until a first message, so prime it with
	// counter 0, then jump just under the future limit.
	if _, err := c.bob.Receive(header); err != nil {
		t.Fatal(err)
	}
	header, _, err = c.alice.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	header.MessageNumber = MaxSkippedKeys + 2
	if _, err := c.bob.Receive(header); !errors.Is(err, ErrTooManySkipped) {
		t.Fatalf("want ErrTooManySkipped, got %v", err)
	}
}

func TestResponderCanSendFirst(t *testing.T) {
	c := newConversation(t)
	header, bobKeys, err := c.bob.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	aliceKeys, err := c.alice.Receive(header)
	if err != nil {
		t.Fatalf("alice receive: %v", err)
	}
	if aliceKeys != bobKeys {
		t.Fatal("initial responder message keys differ")
	}
}
