package protobuf_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

func splitFields(t *testing.T, raw []byte) map[protowire.Number]protowire.Type {
	t.Helper()
	fields := map[protowire.Number]protowire.Type{}
	for len(raw) > 0 {
		number, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			t.Fatalf("bad tag: %v", protowire.ParseError(n))
		}
		raw = raw[n:]
		fields[number] = typ
		consumed := protowire.ConsumeFieldValue(number, typ, raw)
		if consumed < 0 {
			t.Fatalf("bad field %d: %v", number, protowire.ParseError(consumed))
		}
		raw = raw[consumed:]
	}
	return fields
}

func bytesField(t *testing.T, raw []byte, number protowire.Number) []byte {
	t.Helper()
	for len(raw) > 0 {
		n, typ, tagLen := protowire.ConsumeTag(raw)
		if tagLen < 0 {
			t.Fatalf("bad tag: %v", protowire.ParseError(tagLen))
		}
		raw = raw[tagLen:]
		if typ == protowire.BytesType {
			value, valueLen := protowire.ConsumeBytes(raw)
			if valueLen < 0 {
				t.Fatalf("bad bytes: %v", protowire.ParseError(valueLen))
			}
			if n == number {
				return value
			}
			raw = raw[valueLen:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(n, typ, raw)
		if consumed < 0 {
			t.Fatalf("bad field %d: %v", n, protowire.ParseError(consumed))
		}
		raw = raw[consumed:]
	}
	t.Fatalf("field %d not found", number)
	return nil
}

func roundTrip(t *testing.T, message proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	clone := message.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(raw, clone); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !proto.Equal(message, clone) {
		t.Fatalf("round trip mismatch:\n got %v\nwant %v", clone, message)
	}
	return raw
}

func TestHandshakeMessageWireFields(t *testing.T) {
	ephemeral := bytes.Repeat([]byte{0x11}, 32)
	static := bytes.Repeat([]byte{0x22}, 32)
	payload := []byte("synthetic payload")

	hello := &protobuf.HandshakeMessage{
		ClientHello: &protobuf.HandshakeMessage_ClientHello{Ephemeral: ephemeral},
	}
	raw := roundTrip(t, hello)
	if typ, ok := splitFields(t, raw)[2]; !ok || typ != protowire.BytesType {
		t.Fatalf("HandshakeMessage.clientHello must be field 2 bytes, got %v", splitFields(t, raw))
	}
	if got := bytesField(t, bytesField(t, raw, 2), 1); !bytes.Equal(got, ephemeral) {
		t.Fatalf("ClientHello.ephemeral = %x", got)
	}

	server := &protobuf.HandshakeMessage{
		ServerHello: &protobuf.HandshakeMessage_ServerHello{
			Ephemeral: ephemeral, Static: static, Payload: payload,
		},
	}
	raw = roundTrip(t, server)
	inner := bytesField(t, raw, 3)
	for number, want := range map[protowire.Number][]byte{1: ephemeral, 2: static, 3: payload} {
		if got := bytesField(t, inner, number); !bytes.Equal(got, want) {
			t.Fatalf("ServerHello field %d = %x, want %x", number, got, want)
		}
	}

	finish := &protobuf.HandshakeMessage{
		ClientFinish: &protobuf.HandshakeMessage_ClientFinish{Static: static, Payload: payload},
	}
	raw = roundTrip(t, finish)
	inner = bytesField(t, raw, 4)
	if got := bytesField(t, inner, 1); !bytes.Equal(got, static) {
		t.Fatalf("ClientFinish.static = %x", got)
	}
	if got := bytesField(t, inner, 2); !bytes.Equal(got, payload) {
		t.Fatalf("ClientFinish.payload = %x", got)
	}
}

func TestCertChainWireFields(t *testing.T) {
	serial, issuer, notBefore, notAfter := uint32(2), uint32(1), uint64(100), uint64(200)
	details, err := proto.Marshal(&protobuf.CertChain_NoiseCertificate_Details{
		Serial:       &serial,
		IssuerSerial: &issuer,
		Key:          bytes.Repeat([]byte{0x33}, 32),
		NotBefore:    &notBefore,
		NotAfter:     &notAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	fields := splitFields(t, details)
	for number, want := range map[protowire.Number]protowire.Type{
		1: protowire.VarintType, 2: protowire.VarintType, 3: protowire.BytesType,
		4: protowire.VarintType, 5: protowire.VarintType,
	} {
		if fields[number] != want {
			t.Fatalf("Details field %d type = %v, want %v (all fields: %v)", number, fields[number], want, fields)
		}
	}

	cert := func(signature byte) *protobuf.CertChain_NoiseCertificate {
		return &protobuf.CertChain_NoiseCertificate{
			Details:   details,
			Signature: bytes.Repeat([]byte{signature}, 64),
		}
	}
	chain := &protobuf.CertChain{Leaf: cert(0x44), Intermediate: cert(0x55)}
	raw := roundTrip(t, chain)

	if leaf := splitFields(t, bytesField(t, raw, 1)); leaf[1] != protowire.BytesType || leaf[2] != protowire.BytesType {
		t.Fatalf("leaf certificate fields = %v", leaf)
	}
	if intermediate := splitFields(t, bytesField(t, raw, 2)); intermediate[1] != protowire.BytesType || intermediate[2] != protowire.BytesType {
		t.Fatalf("intermediate certificate fields = %v", intermediate)
	}
}
