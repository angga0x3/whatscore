package signal

import "testing"

func BenchmarkEncryptMessage(b *testing.B) {
	keys := testMessageKeys()
	header := testHeader()
	sender, receiver := testIdentities()
	plaintext := make([]byte, 256)
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		if _, err := EncryptMessage(keys, header, plaintext, sender, receiver); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptMessage(b *testing.B) {
	keys := testMessageKeys()
	header := testHeader()
	sender, receiver := testIdentities()
	plaintext := make([]byte, 256)
	wire, err := EncryptMessage(keys, header, plaintext, sender, receiver)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		if _, err := DecryptMessage(wire, keys, sender, receiver); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRatchetOutbound(b *testing.B) {
	c := newConversation(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.alice.NextOutbound(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRatchetReceive(b *testing.B) {
	c := newConversation(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		header, _, err := c.alice.NextOutbound()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.bob.Receive(header); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStateRoundTrip(b *testing.B) {
	c := newConversation(b)
	sender, receiver := testIdentities()
	plaintext := make([]byte, 256)
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		wire, err := c.alice.Encrypt(plaintext, sender, receiver)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.bob.Decrypt(wire, sender, receiver); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStateMarshal(b *testing.B) {
	fixture := newStateFixture(b, 100)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := fixture.bob.MarshalBinary(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStateUnmarshal(b *testing.B) {
	raw, err := newStateFixture(b, 100).bob.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseState(raw); err != nil {
			b.Fatal(err)
		}
	}
}
