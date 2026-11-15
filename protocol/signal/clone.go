package signal

// Clone returns a deep copy of the state. Callers use it to attempt a
// decryption without mutating the live ratchet.
func (s *State) Clone() (*State, error) {
	raw, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return ParseState(raw)
}
