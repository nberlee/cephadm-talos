// Package cephx generates CephX secret keys without needing ceph-authtool.
package cephx

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
