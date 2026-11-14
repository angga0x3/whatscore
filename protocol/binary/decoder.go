package binary

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// Decode reads one frame, inflating it when the flag requests compression.
func (c *codec) Decode(r io.Reader) (*Node, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxNodeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("binary: read frame: %w", err)
	}
	if len(data) > MaxNodeBytes {
		return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrTooLarge, MaxNodeBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty frame", ErrTruncated)
	}

	payload := data[1:]
	if data[0]&2 != 0 {
		zr, zerr := zlib.NewReader(bytes.NewReader(payload))
		if zerr != nil {
			return nil, fmt.Errorf("%w: zlib header: %w", ErrInvalidNode, zerr)
		}
		defer func() { _ = zr.Close() }()
		payload, zerr = io.ReadAll(io.LimitReader(zr, MaxNodeBytes+1))
		if zerr != nil {
			return nil, fmt.Errorf("%w: inflate: %w", ErrInvalidNode, zerr)
		}
		if len(payload) > MaxNodeBytes {
			return nil, fmt.Errorf("%w: inflated frame exceeds %d bytes", ErrTooLarge, MaxNodeBytes)
		}
	}

	d := &decoder{dict: c.dict, buf: payload}
	node, err := d.readNode(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(d.buf) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrInvalidNode, len(d.buf)-d.pos)
	}
	return node, nil
}

type decoder struct {
	dict  *Dictionary
	buf   []byte
	pos   int
	nodes int
}

func (d *decoder) readNode(depth int) (*Node, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrTooLarge, MaxDepth)
	}
	if d.nodes >= MaxNodes {
		return nil, fmt.Errorf("%w: more than %d nodes", ErrTooLarge, MaxNodes)
	}
	d.nodes++

	tagByte, err := d.readByte()
	if err != nil {
		return nil, err
	}
	size, err := d.readListSize(int(tagByte))
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, fmt.Errorf("%w: zero-size node", ErrInvalidNode)
	}

	tag, err := d.readString()
	if err != nil {
		return nil, err
	}
	if tag == "" {
		return nil, fmt.Errorf("%w: empty tag", ErrInvalidNode)
	}

	node := &Node{Tag: tag}
	attrCount := (size - 1) / 2
	if attrCount > 0 {
		node.Attrs = make(Attrs, attrCount)
		for i := 0; i < attrCount; i++ {
			key, err := d.readString()
			if err != nil {
				return nil, err
			}
			value, err := d.readString()
			if err != nil {
				return nil, err
			}
			node.Attrs[key] = value
		}
	}

	if size%2 == 0 {
		contentTag, err := d.readByte()
		if err != nil {
			return nil, err
		}
		if isListTag(int(contentTag)) {
			children, err := d.readList(int(contentTag), depth+1)
			if err != nil {
				return nil, err
			}
			node.Children = children
		} else {
			content, err := d.readContent(int(contentTag))
			if err != nil {
				return nil, err
			}
			node.Bytes = content
		}
	}
	return node, nil
}

func (d *decoder) readList(tag, depth int) ([]Node, error) {
	size, err := d.readListSize(tag)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	if size > MaxChildCount {
		return nil, fmt.Errorf("%w: list of %d children", ErrTooLarge, size)
	}
	children := make([]Node, size)
	for i := 0; i < size; i++ {
		child, err := d.readNode(depth)
		if err != nil {
			return nil, err
		}
		children[i] = *child
	}
	return children, nil
}

func (d *decoder) readContent(tag int) ([]byte, error) {
	switch tag {
	case tagBinary8:
		size, err := d.readByte()
		if err != nil {
			return nil, err
		}
		return d.readBytes(int(size))
	case tagBinary20:
		size, err := d.readUint20()
		if err != nil {
			return nil, err
		}
		return d.readBytes(size)
	case tagBinary32:
		size, err := d.readUint32()
		if err != nil {
			return nil, err
		}
		return d.readBytes(int(size))
	default:
		s, err := d.readStringTag(tag)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
}

func (d *decoder) readString() (string, error) {
	tag, err := d.readByte()
	if err != nil {
		return "", err
	}
	return d.readStringTag(int(tag))
}

func (d *decoder) readStringTag(tag int) (string, error) {
	switch {
	case tag == tagListEmpty:
		return "", nil
	case tag >= 1 && tag <= singleByteTokenMax:
		if s, ok := d.dict.Single(byte(tag)); ok {
			return s, nil
		}
		return "", fmt.Errorf("%w: single-byte index %d", ErrUnknownToken, tag)
	case tag >= tagDictionary0 && tag <= tagDictionary3:
		index, err := d.readByte()
		if err != nil {
			return "", err
		}
		if s, ok := d.dict.Double(byte(tag-tagDictionary0), index); ok {
			return s, nil
		}
		return "", fmt.Errorf("%w: dictionary %d index %d", ErrUnknownToken, tag-tagDictionary0, index)
	case tag == tagBinary8:
		size, err := d.readByte()
		if err != nil {
			return "", err
		}
		data, err := d.readBytes(int(size))
		return string(data), err
	case tag == tagBinary20:
		size, err := d.readUint20()
		if err != nil {
			return "", err
		}
		data, err := d.readBytes(size)
		return string(data), err
	case tag == tagBinary32:
		size, err := d.readUint32()
		if err != nil {
			return "", err
		}
		data, err := d.readBytes(int(size))
		return string(data), err
	case tag == tagNibble8 || tag == tagHex8:
		return d.readPacked(tag)
	case tag == tagJIDPair:
		return d.readJIDPair()
	case tag == tagADJID:
		return d.readADJID()
	case tag == tagFBJID:
		return d.readFBJID()
	case tag == tagInteropJID:
		return d.readInteropJID()
	default:
		return "", fmt.Errorf("%w: tag %d", ErrUnknownToken, tag)
	}
}

func (d *decoder) readPacked(tag int) (string, error) {
	start, err := d.readByte()
	if err != nil {
		return "", err
	}
	count := int(start & 0x7f)
	raw, err := d.readBytes(count)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, count*2)
	for _, b := range raw {
		hi, err := unpack(tag, int(b>>4))
		if err != nil {
			return "", err
		}
		lo, err := unpack(tag, int(b&0x0f))
		if err != nil {
			return "", err
		}
		out = append(out, hi, lo)
	}
	if start&0x80 != 0 && len(out) > 0 {
		out = out[:len(out)-1]
	}
	return string(out), nil
}

func unpack(tag, value int) (byte, error) {
	if tag == tagNibble8 {
		switch {
		case value < 10:
			return byte('0' + value), nil
		case value == 10:
			return '-', nil
		case value == 11:
			return '.', nil
		case value == 15:
			return 0, nil
		default:
			return 0, fmt.Errorf("%w: nibble %d", ErrInvalidNode, value)
		}
	}
	switch {
	case value < 10:
		return byte('0' + value), nil
	case value < 16:
		return byte('A' + value - 10), nil
	default:
		return 0, fmt.Errorf("%w: hex %d", ErrInvalidNode, value)
	}
}

func (d *decoder) readJIDPair() (string, error) {
	user, err := d.readString()
	if err != nil {
		return "", err
	}
	server, err := d.readString()
	if err != nil {
		return "", err
	}
	if server == "" {
		return "", fmt.Errorf("%w: JID pair without server", ErrInvalidNode)
	}
	return user + "@" + server, nil
}

func (d *decoder) readADJID() (string, error) {
	domain, err := d.readByte()
	if err != nil {
		return "", err
	}
	device, err := d.readByte()
	if err != nil {
		return "", err
	}
	user, err := d.readString()
	if err != nil {
		return "", err
	}
	server := "s.whatsapp.net"
	switch domain {
	case 1:
		server = "lid"
	case 2:
		server = "hosted"
	case 3:
		server = "hosted.lid"
	}
	return joinJID(user, server, uint16(device)), nil
}

func (d *decoder) readFBJID() (string, error) {
	user, err := d.readString()
	if err != nil {
		return "", err
	}
	device, err := d.readUint16()
	if err != nil {
		return "", err
	}
	server, err := d.readString()
	if err != nil {
		return "", err
	}
	return joinJID(user, server, uint16(device)), nil
}

func (d *decoder) readInteropJID() (string, error) {
	user, err := d.readString()
	if err != nil {
		return "", err
	}
	device, err := d.readUint16()
	if err != nil {
		return "", err
	}
	integrator, err := d.readUint16()
	if err != nil {
		return "", err
	}
	server := "interop"
	if d.pos < len(d.buf) {
		server, err = d.readString()
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%d-%s:%d@%s", integrator, user, device, server), nil
}

func joinJID(user, server string, device uint16) string {
	if device > 0 {
		return fmt.Sprintf("%s:%d@%s", user, device, server)
	}
	return user + "@" + server
}

func (d *decoder) readListSize(tag int) (int, error) {
	switch tag {
	case tagListEmpty:
		return 0, nil
	case tagList8:
		size, err := d.readByte()
		return int(size), err
	case tagList16:
		return d.readUint16()
	default:
		return 0, fmt.Errorf("%w: list tag %d", ErrInvalidNode, tag)
	}
}

func isListTag(tag int) bool {
	return tag == tagListEmpty || tag == tagList8 || tag == tagList16
}

func (d *decoder) peekByte() (byte, error) {
	if d.pos >= len(d.buf) {
		return 0, fmt.Errorf("%w: reading byte at %d", ErrTruncated, d.pos)
	}
	return d.buf[d.pos], nil
}

func (d *decoder) readByte() (byte, error) {
	b, err := d.peekByte()
	if err != nil {
		return 0, err
	}
	d.pos++
	return b, nil
}

func (d *decoder) readBytes(n int) ([]byte, error) {
	if n < 0 || n > MaxNodeBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, n)
	}
	if d.pos+n > len(d.buf) {
		return nil, fmt.Errorf("%w: need %d bytes at %d", ErrTruncated, n, d.pos)
	}
	out := d.buf[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

func (d *decoder) readUint16() (int, error) {
	b, err := d.readBytes(2)
	if err != nil {
		return 0, err
	}
	return int(b[0])<<8 | int(b[1]), nil
}

func (d *decoder) readUint20() (int, error) {
	b, err := d.readBytes(3)
	if err != nil {
		return 0, err
	}
	return int(b[0]&0x0f)<<16 | int(b[1])<<8 | int(b[2]), nil
}

func (d *decoder) readUint32() (int, error) {
	b, err := d.readBytes(4)
	if err != nil {
		return 0, err
	}
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]), nil
}
