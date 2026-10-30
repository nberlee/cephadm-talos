package orch

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/daemons"
)

// SupportedCeph is the only Ceph release this build supports (docs/support.md).
const SupportedCeph = "20.2.4"

// SupportedArch is the only CPU architecture this build supports, as `uname -m` reports it.
const SupportedArch = "x86_64"

// imageInfo is an image reference resolved to a digest and probed.
type imageInfo struct {
	Ref     string // name@sha256:...
	Version string // Ceph version, e.g. 20.2.4
	Arch    string // uname -m inside the image on the probed node
}

var cephVersionRe = regexp.MustCompile(`ceph version (\d+\.\d+\.\d+)`)

// resolveImage pulls ref on node, pinning it to the digest Talos resolved, and
// runs `ceph --version` in it. A tag the node already has resolves to the
// digest it pulled earlier; refresh pulls it again.
func (o *Orch) resolveImage(ctx context.Context, node, ref string, refresh bool) (imageInfo, error) {
	if o.Talos.DryRun {
		o.printf("# pull %s on %s (refresh %t), pin its digest and probe its Ceph version\n", ref, node, refresh)

		return imageInfo{Ref: ref}, nil
	}

	pctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	o.printf("pulling %s on %s\n", ref, node)

	pinned, err := o.Talos.PullImage(pctx, node, ref, refresh)
	if err != nil {
		return imageInfo{}, err
	}

	id := randHex(3)
	doc := daemons.Probe(fmt.Sprintf("ceph-%s-probe-%s", o.St.Short(), id), pinned)

	res, err := o.runJob(ctx, node, doc, id, 5*time.Minute)
	if err != nil {
		return imageInfo{}, fmt.Errorf("probing %s: %w", pinned, err)
	}

	info, err := parseProbe(res.Output)
	if err != nil {
		return imageInfo{}, fmt.Errorf("probing %s: %w", pinned, err)
	}

	info.Ref = pinned
	o.printf("%s is Ceph %s (%s)\n", pinned, info.Version, info.Arch)

	return info, nil
}

func parseProbe(out string) (imageInfo, error) {
	var info imageInfo

	if m := cephVersionRe.FindStringSubmatch(out); m != nil {
		info.Version = m[1]
	}

	for _, l := range strings.Split(out, "\n") {
		if a, ok := strings.CutPrefix(strings.TrimSpace(l), "arch "); ok {
			info.Arch = strings.TrimSpace(a)
		}
	}

	if info.Version == "" || info.Arch == "" {
		return info, fmt.Errorf("unexpected probe output: %q", out)
	}

	return info, nil
}

// gateImage refuses a Ceph image that this build does not support.
func (o *Orch) gateImage(info imageInfo) error {
	if o.SkipVersionCheck || o.Talos.DryRun {
		return nil
	}

	if info.Version != SupportedCeph {
		return fmt.Errorf("%s is Ceph %s; cephadm-talos supports only Ceph %s (--skip-version-check for testing)", info.Ref, info.Version, SupportedCeph)
	}

	if info.Arch != SupportedArch {
		return fmt.Errorf("%s runs as %s; cephadm-talos supports only %s for now", info.Ref, info.Arch, SupportedArch)
	}

	return nil
}

// gateCluster refuses to deploy onto a cluster whose image is not supported.
func (o *Orch) gateCluster() error {
	return o.gateImage(imageInfo{Ref: o.St.Image, Version: o.St.CephVersion, Arch: o.St.Arch})
}
