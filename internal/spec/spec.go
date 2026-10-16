// Package spec renders the Talos machine config documents that make up a Ceph daemon.
//
// Only the fields cephadm-talos needs are modelled; see the Talos ContainerConfig,
// EtcFileConfig and UserVolumeConfig reference for the full schemas.
package spec

import (
	"bytes"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// VolumeName is the per-node UserVolumeConfig (directory) holding /var/lib/ceph.
const VolumeName = "ceph"

// Header is common to all documents.
type Header struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Name       string `yaml:"name"`
	Patch      string `yaml:"$patch,omitempty"`
}

// UserVolumeConfig is a directory-backed user volume, mounted at /var/mnt/<name>.
type UserVolumeConfig struct {
	Header     `yaml:",inline"`
	VolumeType string `yaml:"volumeType"`
}

// EtcFileConfig writes a file below /etc on the node.
type EtcFileConfig struct {
	Header   `yaml:",inline"`
	Mode     yamlOctal `yaml:"mode"`
	Contents string    `yaml:"contents"`
}

// ContainerConfig declares a container run by Talos in the taloscontainers namespace.
type ContainerConfig struct {
	Header      `yaml:",inline"`
	Image       string     `yaml:"image,omitempty"`
	Entrypoint  []string   `yaml:"entrypoint,omitempty"`
	Args        []string   `yaml:"args,omitempty"`
	Environment []string   `yaml:"environment,omitempty"`
	Mounts      []Mount    `yaml:"mounts,omitempty"`
	Security    *Security  `yaml:"security,omitempty"`
	Network     *Network   `yaml:"network,omitempty"`
	Resources   *Resources `yaml:"resources,omitempty"`
	DependsOn   *DependsOn `yaml:"dependsOn,omitempty"`
}

// Mount has exactly one of its sources set.
type Mount struct {
	UserVolume *UserVolumeMount `yaml:"userVolume,omitempty"`
	Tmpfs      *TmpfsMount      `yaml:"tmpfs,omitempty"`
	HostPath   *HostPathMount   `yaml:"hostPath,omitempty"`
}

type UserVolumeMount struct {
	Name        string   `yaml:"name"`
	Destination string   `yaml:"destination"`
	Options     []string `yaml:"options,omitempty"`
}

type TmpfsMount struct {
	Destination string   `yaml:"destination"`
	Size        string   `yaml:"size,omitempty"`
	Options     []string `yaml:"options,omitempty"`
}

type HostPathMount struct {
	Source      string   `yaml:"source"`
	Destination string   `yaml:"destination"`
	Options     []string `yaml:"options,omitempty"`
}

type Security struct {
	Profile string `yaml:"profile,omitempty"`
}

type Network struct {
	Mode string `yaml:"mode,omitempty"`
}

type Resources struct {
	Limits *Limits `yaml:"limits,omitempty"`
}

type Limits struct {
	CPU    string `yaml:"cpu,omitempty"`
	Memory string `yaml:"memory,omitempty"`
}

type DependsOn struct {
	Paths      []string `yaml:"paths,omitempty"`
	Networks   []string `yaml:"networks,omitempty"`
	Time       *bool    `yaml:"time,omitempty"`
	Containers []string `yaml:"containers,omitempty"`
}

// yamlOctal renders a file mode as 0o644, like the Talos examples.
type yamlOctal uint32

func (m yamlOctal) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("0o%o", uint32(m))}, nil
}

func header(kind, name string) Header {
	return Header{APIVersion: "v1alpha1", Kind: kind, Name: name}
}

// CephVolume returns the directory user volume backing /var/lib/ceph on every Ceph node.
func CephVolume() UserVolumeConfig {
	return UserVolumeConfig{Header: header("UserVolumeConfig", VolumeName), VolumeType: "directory"}
}

// CephConf returns the EtcFileConfig for /etc/ceph/ceph.conf.
func CephConf(contents string) EtcFileConfig {
	return EtcFileConfig{Header: header("EtcFileConfig", "ceph/ceph.conf"), Mode: 0o644, Contents: contents}
}

// Delete returns a document that removes the named document of the given kind.
func Delete(kind, name string) Header {
	h := header(kind, name)
	h.Patch = "delete"

	return h
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateName checks the ContainerConfig name rules (1-63 chars, lowercase alnum and '-').
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid container name %q: must be 1-63 chars of [a-z0-9-], starting and ending alphanumeric", name)
	}

	return nil
}

// Render marshals documents into one multi-document YAML patch.
func Render(docs ...any) ([]byte, error) {
	var buf bytes.Buffer

	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)

	for _, d := range docs {
		if c, ok := d.(ContainerConfig); ok {
			if err := ValidateName(c.Name); err != nil {
				return nil, err
			}
		}

		if err := enc.Encode(d); err != nil {
			return nil, err
		}
	}

	if err := enc.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
