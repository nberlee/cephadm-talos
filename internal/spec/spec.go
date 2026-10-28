// Package spec builds the Talos machine config documents cephadm-talos applies,
// using the machinery document types, and renders them into patches.
//
// Only the `$patch: delete` document has no machinery type; it is Header.
package spec

import (
	"bytes"
	"fmt"

	"github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
	"github.com/siderolabs/talos/pkg/machinery/config/types/block"
	"github.com/siderolabs/talos/pkg/machinery/config/types/container"
	"github.com/siderolabs/talos/pkg/machinery/config/types/runtime"
	"github.com/siderolabs/talos/pkg/machinery/config/validation"
	blockres "github.com/siderolabs/talos/pkg/machinery/resources/block"
	"gopkg.in/yaml.v3"
)

// VolumeName is the per-node UserVolumeConfig (directory) holding /var/lib/ceph.
const VolumeName = "ceph"

// ContainerConfig is a container run by Talos in the taloscontainers namespace.
type ContainerConfig = container.ContainerConfigV1Alpha1

// Mount is one mount of a container.
type Mount = container.ContainerMount

// Container returns a ContainerConfig with a name and an image.
func Container(name, image string) *ContainerConfig {
	c := container.NewContainerConfigV1Alpha1()
	c.MetaName, c.ContainerImage = name, image

	return c
}

// UserVolume mounts a user volume.
func UserVolume(name, destination string, options ...string) Mount {
	return Mount{UserVolumeMount: &container.UserVolumeMount{VolumeName: name, MountDestination: destination, MountOpts: options}}
}

// HostPath bind-mounts a host path.
func HostPath(source, destination string, options ...string) Mount {
	return Mount{HostPathMount: &container.HostPathMount{MountSource: source, MountDestination: destination, MountOpts: options}}
}

// Tmpfs mounts an empty tmpfs.
func Tmpfs(destination string) Mount {
	return Mount{TmpfsMount: &container.TmpfsMount{MountDestination: destination}}
}

// Restricted is the restricted profile (no capabilities, read-only rootfs), plus capabilities.
func Restricted(add ...string) *container.ContainerSecurity {
	s := &container.ContainerSecurity{SecurityProfile: config.ContainerSecurityProfileRestricted}
	if len(add) > 0 {
		s.SecurityCapabilities = &container.ContainerCapabilities{CapabilitiesAddConfig: add}
	}

	return s
}

// Privileged is the privileged profile (all grantable capabilities, all devices).
func Privileged() *container.ContainerSecurity {
	return &container.ContainerSecurity{SecurityProfile: config.ContainerSecurityProfilePrivileged}
}

// HostNetwork shares the host network namespace.
func HostNetwork() *container.ContainerNetwork {
	return &container.ContainerNetwork{NetworkMode: config.ContainerNetworkModeHost}
}

// RunAs runs the container's process as uid and gid.
func RunAs(uid, gid int32) *container.ContainerRunAs {
	return &container.ContainerRunAs{RunAsUID: &uid, RunAsGID: &gid}
}

// CephVolume returns the directory user volume backing /var/lib/ceph on every Ceph node.
func CephVolume() *block.UserVolumeConfigV1Alpha1 {
	v := block.NewUserVolumeConfigV1Alpha1()
	v.MetaName = VolumeName
	t := blockres.VolumeTypeDirectory
	v.VolumeType = &t

	return v
}

// EtcFile writes a file below /etc on the node.
func EtcFile(name string, mode uint32, contents string) *runtime.EtcFileConfigV1Alpha1 {
	f := runtime.NewEtcFileConfigV1Alpha1(name)
	f.FileMode, f.Contents = runtime.EtcFileMode(mode), contents

	return f
}

// CephConf returns the EtcFileConfig for /etc/ceph/ceph.conf.
func CephConf(contents string) *runtime.EtcFileConfigV1Alpha1 {
	return EtcFile("ceph/ceph.conf", 0o644, contents)
}

// Header is the `$patch: delete` document that removes a named document.
type Header struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Name       string `yaml:"name"`
	Patch      string `yaml:"$patch,omitempty"`
}

// Delete returns a document that removes the named document of the given kind.
func Delete(kind, name string) Header {
	return Header{APIVersion: "v1alpha1", Kind: kind, Name: name, Patch: "delete"}
}

// Render validates machinery documents and marshals all documents into one
// multi-document YAML patch.
func Render(docs ...any) ([]byte, error) {
	var buf bytes.Buffer

	for _, d := range docs {
		var (
			b   []byte
			err error
		)

		switch d := d.(type) {
		case Header:
			b, err = yaml.Marshal(d)
		case config.Document:
			if v, ok := d.(config.Validator); ok {
				if _, err := v.Validate(validationMode{}); err != nil {
					return nil, fmt.Errorf("%s %s: %w", d.Kind(), name(d), err)
				}
			}

			b, err = encoder.NewEncoder(d, encoder.WithComments(encoder.CommentsDisabled)).Encode()
		default:
			return nil, fmt.Errorf("render: unsupported document %T", d)
		}

		if err != nil {
			return nil, err
		}

		buf.WriteString("---\n")
		buf.Write(b)
	}

	return buf.Bytes(), nil
}

func name(d config.Document) string {
	if n, ok := d.(config.NamedDocument); ok {
		return n.Name()
	}

	return ""
}

// validationMode is a metal node, which every Ceph node is.
type validationMode struct{}

func (validationMode) String() string        { return "metal" }
func (validationMode) RequiresInstall() bool { return true }
func (validationMode) InContainer() bool     { return false }

var _ validation.RuntimeMode = validationMode{}
