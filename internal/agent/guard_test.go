package agent

import (
	"context"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// a mgr's guard (plan 04, step 5, item 2b) is admitted only as rendered: its
// mgr's dependency, no capabilities, no mounts
func TestAMgrGuardIsAdmittedExactly(t *testing.T) {
	n, _, _ := testNodeFake(t)
	ctx := context.Background()

	appr, err := n.Approval(ctx)
	must(t, err)

	st := state.New(testFSID)
	st.Image = testImage
	mgr := state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1"}
	mon := state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"}
	names := []string{st.DocName(mgr), st.DocName(mon)}

	doc := func(c *spec.ContainerConfig) Doc {
		return Doc{Kind: "ContainerConfig", Name: c.MetaName, YAML: yamlOf(t, c)}
	}

	if err := n.Policy.Check([]Doc{doc(render.MgrGuard(st, mgr, testImage))}, nil, names, appr); err != nil {
		t.Fatalf("the guard as rendered: %v", err)
	}

	for what, change := range map[string]func(c *spec.ContainerConfig){
		"a capability":         func(c *spec.ContainerConfig) { c.SecurityConfig = spec.Restricted("NET_ADMIN") },
		"a mount":              func(c *spec.ContainerConfig) { c.MountsConfig = []spec.Mount{spec.HostPath("/dev", "/dev")} },
		"another dependency":   func(c *spec.ContainerConfig) { c.DependsOnConfig.ContainersConfig[0].DependencyName = st.DocName(mon) },
		"another command":      func(c *spec.ContainerConfig) { c.ContainerEntrypoint = []string{"/bin/bash", "-c", "sleep infinity"} },
		"more environment":     func(c *spec.ContainerConfig) { c.ContainerEnvironment = append(c.ContainerEnvironment, "X=1") },
		"another host's guard": func(c *spec.ContainerConfig) { c.ContainerEnvironment[1] = "ID=h2" },
	} {
		c := render.MgrGuard(st, mgr, testImage)
		change(c)

		if err := n.Policy.Check([]Doc{doc(c)}, nil, names, appr); err == nil {
			t.Errorf("a guard with %s admitted", what)
		}
	}

	// not without its mgr on the node
	if err := n.Policy.Check([]Doc{doc(render.MgrGuard(st, mgr, testImage))}, nil, []string{st.DocName(mon)}, appr); err == nil {
		t.Error("a guard admitted without its mgr")
	}
}
