// Package cbc implements the AES-CBC + PKCS#7 payload primitive shared by the
// Signal and media envelopes.
package cbc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// BlockSize is the AES block size.
const BlockSize = aes.BlockSize

// ErrInvalidCiphertext is returned for bad lengths or padding.
var ErrInvalidCiphertext = errors.New("cbc: invalid ciphertext")

// Encrypt pads plaintext with PKCS#7 and encrypts it with AES-CBC.
func Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := newBlock(key, iv)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// Decrypt decrypts AES-CBC data and validates every PKCS#7 padding byte.
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := newBlock(key, iv)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidCiphertext, len(ciphertext))
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	padding := int(out[len(out)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(out) {
		return nil, fmt.Errorf("%w: padding %d", ErrInvalidCiphertext, padding)
	}
	for _, b := range out[len(out)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("%w: inconsistent padding", ErrInvalidCiphertext)
		}
	}
	return out[:len(out)-padding], nil
}

func newBlock(key, iv []byte) (cipher.Block, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key is %d bytes", ErrInvalidCiphertext, len(key))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%w: iv is %d bytes", ErrInvalidCiphertext, len(iv))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCiphertext, err)
	}
	return block, nil
}
