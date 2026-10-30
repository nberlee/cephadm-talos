package main

// Spike for plan 03, step 0 (temporary, removed in step 1): run inside a container
// with the agent's identity (machinedAccess, uid 50, restricted) and try, with
// os:reader and with os:admin over the local machined socket, to apply a
// document and to exec in the node's mon container.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/role"

	"github.com/nberlee/cephadm-talos/internal/talos"
)

func spike03Agent(ctx context.Context) error {
	for _, r := range []role.Role{role.Reader, role.Admin} {
		c := &talos.Client{Dial: talos.DialSocket(constants.MachineSocketPath), Roles: []role.Role{r}}

		doc := fmt.Sprintf("apiVersion: v1alpha1\nkind: EtcFileConfig\nname: ceph/talos/spike03-%s.txt\nmode: 0644\ncontents: |\n  applied %s\n",
			strings.TrimPrefix(string(r), "os:"), time.Now().UTC().Format(time.RFC3339))
		start := time.Now()
		err := c.Patch(ctx, "", []byte(doc))
		fmt.Printf("%s apply: err=%v (%s)\n", r, err, time.Since(start).Round(time.Millisecond))

		st, err := c.ContainerStatuses(ctx, "")
		if err != nil {
			fmt.Printf("%s list: err=%v\n", r, err)
			continue
		}

		for name := range st {
			if !strings.Contains(name, "-mon-") {
				continue
			}

			var out, errb bytes.Buffer

			start = time.Now()
			code, err := c.Exec(ctx, "", name, []string{"ls", "/var/run/ceph"}, nil, &out, &errb)
			fmt.Printf("%s exec ls in %s: code=%d err=%v out=%q (%s)\n", r, name, code, err, strings.TrimSpace(out.String()), time.Since(start).Round(time.Millisecond))

			for _, sock := range strings.Fields(out.String()) {
				if !strings.HasSuffix(sock, ".asok") {
					continue
				}

				out.Reset()
				code, err = c.Exec(ctx, "", name, []string{"ceph", "--admin-daemon", "/var/run/ceph/" + sock, "version"}, nil, &out, &errb)
				fmt.Printf("%s exec asok version: code=%d err=%v out=%q\n", r, code, err, strings.TrimSpace(out.String()))
			}
		}

		c.Close() //nolint:errcheck
	}

	return nil
}
