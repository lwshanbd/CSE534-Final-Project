package shadowsocks

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var errEmptyPassword = errors.New("empty key")

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}

func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newChacha20Poly1305(key []byte, salt []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}
	subkey := make([]byte, len(key))
	hkdfSHA1(key, salt, []byte("ss-subkey"), subkey)
	return chacha20poly1305.New(subkey)
}

type cipherInfo struct {
	keyLen  int
	newAEAD func(key []byte, salt []byte) (cipher.AEAD, error)
}

var cipherMethod = map[string]*cipherInfo{
	"Chacha20Poly1305": {32, newChacha20Poly1305},
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "Chacha20Poly1305"
	}
	_, ok := cipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

type Cipher struct {
	cipher.AEAD
	key   []byte
	info  *cipherInfo
}

func (c *Cipher) SaltSize() int {
	if ks := len(c.key); ks > 16 {
		return ks
	}
	return 16
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	mi, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := kdf(password, mi.keyLen)

	c = &Cipher{key: key, info: mi}

	return c, nil
}

func (c *Cipher) InitCipher(salt []byte) error {
	mi := c.info
	var err error
	c.AEAD, err = mi.newAEAD(c.key, salt)
	if err != nil {
		return err
	}

	return nil
}



