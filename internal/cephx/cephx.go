// Package cephx generates CephX secret keys without needing ceph-authtool.
package cephx

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// cryptoAES256KRB5 is CEPH_CRYPTO_AES256KRB5 (include/ceph_fs.h), a 32 byte
// secret: the only key type new Ceph v20.2.4+ monmaps allow ("aes256k").
const cryptoAES256KRB5 = 2

// NewKey returns a base64 encoded AES256KRB5 CephX secret, in the same wire
// format `ceph-authtool --gen-print-key` produces:
//
//	le16 type | le32 created.sec | le32 created.nsec | le16 len | len bytes secret
func NewKey() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	return encode(cryptoAES256KRB5, secret, time.Now()), nil
}

func encode(typ uint16, secret []byte, created time.Time) string {
	buf := make([]byte, 0, 12+len(secret))
	buf = binary.LittleEndian.AppendUint16(buf, typ)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(created.Unix()))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(created.Nanosecond()))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(secret)))
	buf = append(buf, secret...)

	return base64.StdEncoding.EncodeToString(buf)
}

// cryptoAES is CEPH_CRYPTO_AES, a 16 byte secret, the type of older keys.
const cryptoAES = 1

// Valid checks that a base64 string is a CephX secret in the wire format
// NewKey produces: an AES (16 byte) or AES256KRB5 (32 byte) key. It never
// returns the key in its error.
func Valid(key string) error {
	// the decoder skips newlines, which would end a keyring line
	if strings.Trim(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != "" {
		return errors.New("cephx: key is not base64")
	}

	b, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil {
		return errors.New("cephx: key is not base64")
	}

	if len(b) < 12 {
		return errors.New("cephx: key too short")
	}

	typ, n := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[10:]))

	switch {
	case len(b) != 12+n:
		return errors.New("cephx: key length does not match its header")
	case typ == cryptoAES && n == 16, typ == cryptoAES256KRB5 && n == 32:
		return nil
	}

	return errors.New("cephx: unknown key type")
}
