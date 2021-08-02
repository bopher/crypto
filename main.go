package crypto

// NewCryptography create a new cryptography instance
func NewCryptography(key string) Crypto {
	if key == "" {
		panic("Key required for cryptography")
	}

	c := new(cryptoDriver)
	c.key = key
	return c
}
