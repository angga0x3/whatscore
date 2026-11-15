package signal

import "errors"

const (
	// MaxSkippedKeys bounds stored message keys for out-of-order delivery.
	MaxSkippedKeys = 1000
	// MaxFutureMessages bounds how far ahead a header counter may jump.
	MaxFutureMessages = 2000
)

var (
	// ErrUninitialized means no sender chain exists yet.
	ErrUninitialized = errors.New("signal: no sender chain")
	// ErrOldMessage means the counter was already consumed.
	ErrOldMessage = errors.New("signal: old message counter")
	// ErrTooFarInFuture means the counter jumped past the limit.
	ErrTooFarInFuture = errors.New("signal: counter too far in the future")
	// ErrTooManySkipped means the skipped-key cache is full.
	ErrTooManySkipped = errors.New("signal: too many skipped keys")
)

// Header is the ratchet header carried with a message (PF-057).
type Header struct {
	RatchetKey          [KeySize]byte
	PreviousChainLength uint32
	MessageNumber       uint32
}

type receiverChain struct {
	chain ChainKey
	index uint32
}

type skippedKey struct {
	ratchet [KeySize]byte
	index   uint32
}

// State is one Double Ratchet session. It is not safe for concurrent use; a
// session actor owns it (PF-057, PF-058).
type State struct {
	root                RootKey
	senderRatchet       KeyPair
	senderChain         ChainKey
	senderIndex         uint32
	previousChainLength uint32

	receiverChains map[[KeySize]byte]*receiverChain
	skipped        map[skippedKey]MessageKeys
}

// NewInitiator initializes the Alice side for ProcessBundle semantics
// (PF-057): the X3DH chain is the receiver chain for the responder's signed
// prekey, and a fresh sending ratchet derives the first sender chain.
func NewInitiator(root RootKey, theirRatchet [KeySize]byte, chain ChainKey) (*State, error) {
	sending, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return newInitiator(root, theirRatchet, chain, sending)
}

func newInitiator(root RootKey, theirRatchet [KeySize]byte, chain ChainKey, sending KeyPair) (*State, error) {
	nextRoot, senderChain, err := root.CreateChain(sending.Private, theirRatchet)
	if err != nil {
		return nil, err
	}
	return &State{
		root:           nextRoot,
		senderRatchet:  sending,
		senderChain:    senderChain,
		receiverChains: map[[KeySize]byte]*receiverChain{theirRatchet: {chain: chain}},
		skipped:        make(map[skippedKey]MessageKeys),
	}, nil
}

// NewResponder initializes the Bob side (PF-057): the X3DH chain is the first
// sender chain, keyed by the responder's signed prekey.
func NewResponder(root RootKey, ourRatchet KeyPair, chain ChainKey) *State {
	return &State{
		root:           root,
		senderRatchet:  ourRatchet,
		senderChain:    chain,
		receiverChains: make(map[[KeySize]byte]*receiverChain),
		skipped:        make(map[skippedKey]MessageKeys),
	}
}

// NextOutbound derives the next message key and advances the sending chain.
func (s *State) NextOutbound() (Header, MessageKeys, error) {
	if s.senderChain == (ChainKey{}) {
		return Header{}, MessageKeys{}, ErrUninitialized
	}
	header := Header{
		RatchetKey:          s.senderRatchet.Public,
		PreviousChainLength: s.previousChainLength,
		MessageNumber:       s.senderIndex,
	}
	keys, err := DeriveMessageKeys(s.senderChain.MessageKey(), s.senderIndex)
	if err != nil {
		return Header{}, MessageKeys{}, err
	}
	s.senderChain = s.senderChain.Next()
	s.senderIndex++
	return header, keys, nil
}

// Receive resolves the message keys for header, performing a DH ratchet when
// the header carries a new ratchet key and caching skipped keys (PF-058).
func (s *State) Receive(header Header) (MessageKeys, error) {
	key := skippedKey{ratchet: header.RatchetKey, index: header.MessageNumber}
	if keys, ok := s.skipped[key]; ok {
		delete(s.skipped, key)
		return keys, nil
	}

	rc := s.receiverChains[header.RatchetKey]
	if rc == nil {
		if err := s.ratchet(header.RatchetKey); err != nil {
			return MessageKeys{}, err
		}
		rc = s.receiverChains[header.RatchetKey]
	}

	if rc.index > header.MessageNumber {
		return MessageKeys{}, ErrOldMessage
	}
	if header.MessageNumber-rc.index > MaxFutureMessages {
		return MessageKeys{}, ErrTooFarInFuture
	}

	for rc.index < header.MessageNumber {
		if len(s.skipped) >= MaxSkippedKeys {
			return MessageKeys{}, ErrTooManySkipped
		}
		keys, err := DeriveMessageKeys(rc.chain.MessageKey(), rc.index)
		if err != nil {
			return MessageKeys{}, err
		}
		s.skipped[skippedKey{ratchet: header.RatchetKey, index: rc.index}] = keys
		rc.chain = rc.chain.Next()
		rc.index++
	}

	keys, err := DeriveMessageKeys(rc.chain.MessageKey(), header.MessageNumber)
	if err != nil {
		return MessageKeys{}, err
	}
	rc.chain = rc.chain.Next()
	rc.index++
	return keys, nil
}

func (s *State) ratchet(theirRatchet [KeySize]byte) error {
	nextRoot, receiveChain, err := s.root.CreateChain(s.senderRatchet.Private, theirRatchet)
	if err != nil {
		return err
	}
	newRatchet, err := GenerateKeyPair()
	if err != nil {
		return err
	}
	sendRoot, sendChain, err := nextRoot.CreateChain(newRatchet.Private, theirRatchet)
	if err != nil {
		return err
	}

	previous := uint32(0)
	if s.senderIndex > 0 {
		previous = s.senderIndex - 1
	}
	s.root = sendRoot
	s.senderRatchet = newRatchet
	s.senderChain = sendChain
	s.senderIndex = 0
	s.previousChainLength = previous
	s.receiverChains[theirRatchet] = &receiverChain{chain: receiveChain}
	return nil
}
