package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Role is what a certificate is for within a cluster (plan 03, item 3).
type Role string

const (
	// RoleMgr is a ceph-mgr's module: server and client certificates.
	RoleMgr Role = "mgr"
	// RoleAgent is a node agent: server and client certificates.
	RoleAgent Role = "agent"
	// RoleOperator is the workstation CLI: a client certificate.
	RoleOperator Role = "operator"
)

// identityScheme is the URI scheme of an identity SAN: cephadm-talos://<fsid>/<role>/<name>.
const identityScheme = "cephadm-talos"

// Identity is the cluster, role and name a certificate is issued to. Endpoints
// check it, never the common name; a certificate never implies leadership.
type Identity struct {
	FSID string
	Role Role
	// Name is the host for mgr and agent certificates, and the operator's name.
	Name string
}

// Valid reports whether every part of the identity has the one accepted form.
func (id Identity) Valid() error {
	for _, p := range []string{id.FSID, string(id.Role), id.Name} {
		if !identityPart.MatchString(p) {
			return fmt.Errorf("%q cannot be part of an identity (letters, digits, '.', '_' and '-', not first)", p)
		}
	}

	return nil
}

// ValidName reports whether a host name can be part of an identity.
func ValidName(name string) error {
	if !identityPart.MatchString(name) {
		return fmt.Errorf("host name %q is not supported: it must start with a letter or digit and contain only letters, digits, '.', '_' and '-'", name)
	}

	return nil
}

// URI returns the identity as a URI SAN.
func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: identityScheme, Host: id.FSID, Path: "/" + string(id.Role) + "/" + id.Name}
}

func (id Identity) String() string { return id.URI().String() }

// identityPart is the only form a part of an identity may take, in Go and in
// the mgr module alike: no escapes, no case folding, nothing to canonicalize.
var identityPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// CertIdentity returns the identity carried by a certificate. Any URI SAN whose
// scheme is cephadm-talos in any case counts; there must be exactly one, in the
// exact form cephadm-talos://<fsid>/<role>/<name>.
func CertIdentity(c *x509.Certificate) (Identity, error) {
	var found []Identity

	for _, u := range c.URIs {
		if !strings.EqualFold(u.Scheme, identityScheme) {
			continue
		}

		id, err := parseIdentity(u)
		if err != nil {
			return Identity{}, err
		}

		found = append(found, id)
	}

	switch len(found) {
	case 0:
		return Identity{}, errors.New("certificate carries no cephadm-talos identity")
	case 1:
		return found[0], nil
	default:
		return Identity{}, errors.New("certificate carries more than one cephadm-talos identity")
	}
}

func parseIdentity(u *url.URL) (Identity, error) {
	parts := strings.Split(strings.TrimPrefix(u.String(), identityScheme+"://"), "/")
	if !strings.HasPrefix(u.String(), identityScheme+"://") || len(parts) != 3 {
		return Identity{}, fmt.Errorf("malformed identity %q", u)
	}

	for _, p := range parts {
		if !identityPart.MatchString(p) {
			return Identity{}, fmt.Errorf("malformed identity %q", u)
		}
	}

	return Identity{FSID: parts[0], Role: Role(parts[1]), Name: parts[2]}, nil
}

// Require checks that a certificate carries exactly the given identity. An empty
// Name accepts any name of that cluster and role.
func Require(c *x509.Certificate, want Identity) (Identity, error) {
	got, err := CertIdentity(c)
	if err != nil {
		return Identity{}, err
	}

	if got.FSID != want.FSID || got.Role != want.Role || (want.Name != "" && got.Name != want.Name) {
		return Identity{}, fmt.Errorf("certificate is %s, want %s", got, want)
	}

	return got, nil
}
