// Package cephx generates CephX secret keys without needing ceph-authtool.
package cephx

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Key types (include/ceph_fs.h).
const (
	cryptoAES        = 1 // CEPH_CRYPTO_AES, 16 byte secret (Ceph <= v19)
	cryptoAES256KRB5 = 2 // CEPH_CRYPTO_AES256KRB5, 32 byte secret; Ceph v20 (tentacle) monmaps only allow this ("aes256k")
)

// Key types as named in ceph.conf (auth_*_ciphers).
const (
	KeyAES     = "aes"     // all releases up to and including v20.2.3
	KeyAES256K = "aes256k" // v20.2.4+; new tentacle monmaps allow only this
)

// NewKey returns a base64 encoded CephX secret of the given type, in the same
// wire format `ceph-authtool --gen-print-key` produces:
//
//	le16 type | le32 created.sec | le32 created.nsec | le16 len | len bytes secret
func NewKey(keyType string) (string, error) {
	typ, size := uint16(cryptoAES256KRB5), 32
	if keyType == KeyAES {
		typ, size = cryptoAES, 16
	}

	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	return encode(typ, secret, time.Now()), nil
}

// KeyTypeFor picks the key type for a Ceph image: aes256k unless the tag names
// a release before v20.2.4. Digests and floating tags are assumed to be recent.
func KeyTypeFor(image string) string {
	tag := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		tag = image[i+1:]
	}

	_, tag, ok := strings.Cut(tag, ":")
	if !ok || strings.Contains(image, "@") {
		return KeyAES256K
	}

	var maj, mnr, pat int

	n, _ := fmt.Sscanf(strings.TrimPrefix(tag, "v"), "%d.%d.%d", &maj, &mnr, &pat)

	switch {
	case n == 0:
		return KeyAES256K
	case maj < 20:
		return KeyAES
	case maj == 20 && n == 3 && (mnr < 2 || (mnr == 2 && pat < 4)):
		return KeyAES
	case maj == 20 && n == 2 && mnr < 2:
		return KeyAES
	}

	return KeyAES256K
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
