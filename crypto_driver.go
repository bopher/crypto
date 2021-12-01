package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"time"

	"github.com/bopher/utils"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

// cryptoDriver cryptography driver
type cryptoDriver struct {
	key string
}

func (cryptoDriver) err(format string, args ...interface{}) error {
	return utils.TaggedError([]string{"Crypto"}, format, args...)
}

// Hash make hash for data
func (this cryptoDriver) Hash(data string, algo HashAlgo) (string, error) {
	var hasher hash.Hash
	key := []byte(this.key)

	switch algo {
	case MD4:
		hasher = hmac.New(md4.New, key)
	case MD5:
		hasher = hmac.New(md5.New, key)
	case SHA1:
		hasher = hmac.New(sha1.New, key)
	case SHA256:
		hasher = hmac.New(sha256.New, key)
	case SHA256224:
		hasher = hmac.New(sha256.New224, key)
	case SHA512:
		hasher = hmac.New(sha512.New, key)
	case SHA512224:
		hasher = hmac.New(sha512.New512_224, key)
	case SHA512256:
		hasher = hmac.New(sha512.New512_256, key)
	case SHA384:
		hasher = hmac.New(sha512.New384, key)
	case SHA3224:
		hasher = hmac.New(sha3.New224, key)
	case SHA3256:
		hasher = hmac.New(sha3.New256, key)
	case SHA3384:
		hasher = hmac.New(sha3.New384, key)
	case SHA3512:
		hasher = hmac.New(sha3.New512, key)
	case KECCAK256:
		hasher = hmac.New(sha3.NewLegacyKeccak256, key)
	case KECCAK512:
		hasher = hmac.New(sha3.NewLegacyKeccak512, key)
	}

	if hasher == nil {
		return "", this.err("invalid hasher %s.", algo)
	}

	_, err := hasher.Write([]byte(data))
	if err != nil {
		return "", this.err(err.Error())
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HashFilename make hashed filename based on current timestamp
func (this cryptoDriver) HashFilename(filename string, algo HashAlgo) (string, error) {
	ext := filepath.Ext(filename)
	res, err := this.Hash(fmt.Sprintf("%s-at-%d", filename, time.Now().Nanosecond()), algo)
	if err != nil {
		return "", this.err(err.Error())
	}
	return res + ext, nil
}

// HashSize get hash size for algorithm
// return -1 if invalid algo passed
func (cryptoDriver) HashSize(algo HashAlgo) int {
	switch algo {
	case MD4:
		return md4.Size
	case MD5:
		return md5.Size
	case SHA1:
		return sha1.Size
	case SHA256:
		return sha256.Size
	case SHA256224:
		return sha256.Size224
	case SHA512:
		return sha512.Size
	case SHA512224:
		return sha512.Size224
	case SHA512256:
		return sha512.Size256
	case SHA384:
		return sha512.Size384
	case SHA3224:
		return sha3.New224().Size()
	case SHA3256:
		return sha3.New256().Size()
	case SHA3384:
		return sha3.New384().Size()
	case SHA3512:
		return sha3.New512().Size()
	case KECCAK256:
		return sha3.NewLegacyKeccak256().Size()
	case KECCAK512:
		return sha3.NewLegacyKeccak512().Size()
	}

	return -1
}

// Check check data against hash
func (this cryptoDriver) Check(data string, hash string, algo HashAlgo) (bool, error) {
	res, err := this.Hash(data, algo)
	if err != nil {
		return false, this.err(err.Error())
	}
	return res == hash, nil
}

// Encrypt data
func (this cryptoDriver) Encrypt(data []byte) ([]byte, error) {
	var err error

	// generate key md5
	key, err := this.Hash(this.key, MD5)
	if err != nil {
		return nil, this.err(err.Error())
	}

	// generate cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, this.err(err.Error())
	}

	// generate gcm
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, this.err(err.Error())
	}

	// generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, this.err(err.Error())
	}

	// encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt data
func (this cryptoDriver) Decrypt(data []byte) ([]byte, error) {
	var err error

	// generate key md5
	key, err := this.Hash(this.key, MD5)
	if err != nil {
		return nil, this.err(err.Error())
	}

	// generate cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, this.err(err.Error())
	}

	// generate gcm
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, this.err(err.Error())
	}

	// generate nonce
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, this.err(err.Error())
	}

	return plaintext, nil
}

// EncryptHEX encrypt data and return encrypted value as hex encoded string
func (this cryptoDriver) EncryptHEX(data []byte) (string, error) {
	res, err := this.Encrypt(data)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(res), nil
}

// DecryptHex decrypt data from hex encoded string.
func (this cryptoDriver) DecryptHex(hexString string) ([]byte, error) {
	data, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, this.err(err.Error())
	}
	return this.Decrypt(data)
}

// EncryptBase64 encrypt data and return encrypted value as base64 encoded string
func (this cryptoDriver) EncryptBase64(data []byte) (string, error) {
	res, err := this.Encrypt(data)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(res), nil
}

// DecryptBase64 decrypt data from base64 encoded string.
func (this cryptoDriver) DecryptBase64(base64String string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(base64String)
	if err != nil {
		return nil, this.err(err.Error())
	}
	return this.Decrypt(data)
}
