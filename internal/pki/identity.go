package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
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

// URI returns the identity as a URI SAN.
func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: identityScheme, Host: id.FSID, Path: "/" + string(id.Role) + "/" + id.Name}
}

func (id Identity) String() string { return id.URI().String() }

// CertIdentity returns the identity carried by a certificate. A certificate with
// no identity SAN, or more than one, has none.
func CertIdentity(c *x509.Certificate) (Identity, error) {
	var found []Identity

	for _, u := range c.URIs {
		if u.Scheme != identityScheme {
			continue
		}

		role, name, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
		if !ok || u.Host == "" || name == "" || strings.Contains(name, "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return Identity{}, fmt.Errorf("malformed identity %q", u)
		}

		found = append(found, Identity{FSID: u.Host, Role: Role(role), Name: name})
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
