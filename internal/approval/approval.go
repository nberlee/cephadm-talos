// Package approval is the operator's approval of what the cluster may run
// (plan 03, step 6c): the image digests, and the disks a preparation or zap
// job may use. The CLI signs approvals with a key only the workstation holds;
// every agent pins the public key in its own document and admits images and
// disk jobs only as the highest approval it verified allows.
package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// Version is the approval record's version.
const Version = 1

// Actions a disk entry allows.
const (
	Prepare = "prepare"
	Zap     = "zap"
)

// Approval is what the operator approved.
type Approval struct {
	Version int    `json:"version"`
	FSID    string `json:"fsid"`
	Serial  int64  `json:"serial"`
	// Images are image references by digest ("<repository>@sha256:<hex>")
	Images []string `json:"images"`
	Disks  []Disk   `json:"disks"`
}

// Disk is one approved use of a disk: one job, once (the agent records the
// entry when it admits the job). Since is the serial of the approval that
// first listed the entry; an entry carried into a later approval keeps it.
type Disk struct {
	Host   string `json:"host"`
	Serial string `json:"serial"`
	Action string `json:"action"`
	Since  int64  `json:"since"`
}

// Key names an entry for its one use.
func (d Disk) Key() string { return fmt.Sprintf("%s/%s/%s/%d", d.Host, d.Serial, d.Action, d.Since) }

// Signed is an approval as it travels: its exact JSON encoding and the
// signature over it.
type Signed struct {
	Payload   string `json:"payload"`   // base64 of the approval's JSON
	Signature string `json:"signature"` // base64 Ed25519 signature over the JSON
}

var (
	imageRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	serialRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Check validates an approval's shape.
func (a Approval) Check(fsid string) error {
	if a.Version != Version || a.FSID != fsid || a.Serial <= 0 {
		return errors.New("approval: not a version 1 approval of this cluster")
	}

	for _, img := range a.Images {
		if !imageRe.MatchString(img) {
			return fmt.Errorf("approval: image %q is not a digest reference", img)
		}
	}

	seen := map[string]bool{}

	for _, d := range a.Disks {
		if !hostRe.MatchString(d.Host) || !serialRe.MatchString(d.Serial) || (d.Action != Prepare && d.Action != Zap) || d.Since <= 0 || d.Since > a.Serial {
			return fmt.Errorf("approval: disk entry %+v", d)
		}

		if seen[d.Key()] {
			return fmt.Errorf("approval: disk entry %s twice", d.Key())
		}

		seen[d.Key()] = true
	}

	return nil
}

// Image reports whether an image reference is approved.
func (a Approval) Image(ref string) bool { return slices.Contains(a.Images, ref) }

// Entries returns the entries approving an action on a host's disk, oldest
// first: each allows one job.
func (a Approval) Entries(host, serial, action string) []Disk {
	var out []Disk

	for _, d := range a.Disks {
		if d.Host == host && d.Serial == serial && d.Action == action {
			out = append(out, d)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Since < out[j].Since })

	return out
}

// Entry returns the entry approving an action on a host's disk.
func (a Approval) Entry(host, serial, action string) (Disk, bool) {
	for _, d := range a.Disks {
		if d.Host == host && d.Serial == serial && d.Action == action {
			return d, true
		}
	}

	return Disk{}, false
}

// NewKey creates an approval key: the private key for the workstation, the
// public key for the agents' documents, both base64.
func NewKey() (priv, pub string, err error) {
	p, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(s), base64.StdEncoding.EncodeToString(p), nil
}

// Sign signs an approval.
func Sign(priv string, a Approval) (Signed, error) {
	key, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return Signed{}, errors.New("approval: not an approval key")
	}

	sort.Strings(a.Images)
	sort.Slice(a.Disks, func(i, j int) bool { return a.Disks[i].Key() < a.Disks[j].Key() })

	b, err := json.Marshal(a)
	if err != nil {
		return Signed{}, err
	}

	return Signed{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}, nil
}

// Verify checks a signed approval against the public key and the cluster.
func Verify(pub string, s Signed, fsid string) (Approval, error) {
	key, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Approval{}, errors.New("approval: no approval key")
	}

	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil || len(b) > 1<<20 {
		return Approval{}, errors.New("approval: malformed payload")
	}

	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(key, b, sig) {
		return Approval{}, errors.New("approval: the signature does not verify")
	}

	var a Approval

	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&a); err != nil {
		return Approval{}, fmt.Errorf("approval: %w", err)
	}

	return a, a.Check(fsid)
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
