// Package talos talks to Talos nodes through the machinery Go client.
package talos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/distribution/reference"
	"github.com/siderolabs/talos/pkg/machinery/api/common"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/config/configpatcher"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"github.com/siderolabs/talos/pkg/machinery/resources/files"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
	"github.com/siderolabs/talos/pkg/machinery/role"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// Namespace is the containerd namespace of ContainerConfig containers.
const Namespace = "taloscontainers"

// Conn selects a talosconfig and a context in it; empty fields fall through.
type Conn struct {
	Talosconfig string
	Context     string
}

// Client talks to the Talos nodes of one cluster.
//
// The connection for a node is chosen per field: Flags (the command line)
// first, then Hosts[node] (state.Host overrides), then Default (the cluster).
type Client struct {
	Flags   Conn
	Default Conn
	Hosts   map[string]Conn
	DryRun  bool
	Verbose bool
	Out     io.Writer // where dry-run patches are printed

	mu      sync.Mutex
	clients map[Conn]*client.Client
	// Dial connects to a node; nil uses the talosconfig (tests set a fake node)
	Dial func(ctx context.Context, conn Conn) (*client.Client, error)
	// Roles, if set, are requested on every call (talos-role metadata), e.g.
	// os:reader for the agent on the local machined socket
	Roles []role.Role
}

// ErrNotFound is returned when a resource does not exist on the node.
var ErrNotFound = errors.New("not found")

// ErrApplyDeadline is returned by Patch when the deadline set with
// WithApplyBefore passed before the config was sent: nothing was applied.
var ErrApplyDeadline = errors.New("apply deadline passed before the config was sent")

type applyBeforeKey struct{}

// WithApplyBefore makes Patch send the config only before until: a change the
// agent may make only while a confirmation counts (plan 03, item 5).
func WithApplyBefore(ctx context.Context, until time.Time) context.Context {
	return context.WithValue(ctx, applyBeforeKey{}, until)
}

// ErrExecNotStarted is returned when Talos did not start an exec'd command:
// the container is not running, or stopped while the command was set up.
var ErrExecNotStarted = errors.New("command not started")

// Effective returns the connection settings used for a node.
func (c *Client) Effective(node string) Conn {
	pick := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}

		return ""
	}

	h := c.Hosts[node]

	return Conn{
		Talosconfig: pick(c.Flags.Talosconfig, h.Talosconfig, c.Default.Talosconfig),
		Context:     pick(c.Flags.Context, h.Context, c.Default.Context),
	}
}

// node returns a client for the node and a context that targets it.
func (c *Client) node(ctx context.Context, node, what string) (*client.Client, context.Context, error) {
	if c.DryRun {
		return nil, nil, errors.New("talos: no node access in dry-run")
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "+ talos %s %s\n", node, what)
	}

	conn := c.Effective(node)

	c.mu.Lock()
	defer c.mu.Unlock()

	if cl, ok := c.clients[conn]; ok {
		return cl, c.target(ctx, node), nil
	}

	dial := c.Dial
	if dial == nil {
		dial = newClient
	}

	cl, err := dial(ctx, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("talos client (%s, context %q): %w", conn.Talosconfig, conn.Context, err)
	}

	if c.clients == nil {
		c.clients = map[Conn]*client.Client{}
	}

	c.clients[conn] = cl

	return cl, c.target(ctx, node), nil
}

// target adds the node to call (none for the local socket) and the requested roles.
func (c *Client) target(ctx context.Context, node string) context.Context {
	if node != "" {
		ctx = client.WithNode(ctx, node)
	}

	for _, r := range c.Roles {
		ctx = metadata.AppendToOutgoingContext(ctx, constants.APIAuthzRoleMetadataKey, string(r))
	}

	return ctx
}

// DialSocket connects to a local machined socket, as a container with
// security.machinedAccess sees it (constants.MachineSocketPath).
func DialSocket(path string) func(ctx context.Context, _ Conn) (*client.Client, error) {
	return func(ctx context.Context, _ Conn) (*client.Client, error) {
		return client.New(ctx, client.WithUnixSocket(path), client.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())))
	}
}

func newClient(ctx context.Context, conn Conn) (*client.Client, error) {
	opts := []client.OptionFunc{client.WithDefaultConfig()}
	if conn.Talosconfig != "" {
		opts = []client.OptionFunc{client.WithConfigFromFile(conn.Talosconfig)}
	}

	if conn.Context != "" {
		opts = append(opts, client.WithContextName(conn.Context))
	}

	return client.New(ctx, opts...)
}

// Close closes all connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error

	for _, cl := range c.clients {
		errs = append(errs, cl.Close())
	}

	c.clients = nil

	return errors.Join(errs...)
}

// wrap turns a NotFound from the API into ErrNotFound and names the call.
func wrap(what string, err error) error {
	if err == nil {
		return nil
	}

	if state.IsNotFoundError(err) || status.Code(err) == codes.NotFound {
		return fmt.Errorf("%s: %w: %w", what, ErrNotFound, err)
	}

	return fmt.Errorf("%s: %w", what, err)
}

// Patch applies multi-document machine config patches to a node without rebooting it.
//
// Named documents (ContainerConfig, EtcFileConfig, UserVolumeConfig) are
// strategically merged by kind+name; a document carrying `$patch: delete`
// removes it. The patches are applied in order to the full active config and
// sent as one apply, so a delete followed by an add replaces a document
// atomically, and all other documents are kept.
func (c *Client) Patch(ctx context.Context, node string, patches ...[]byte) error {
	if c.DryRun {
		for _, docs := range patches {
			fmt.Fprintf(c.Out, "# --- patch for node %s ---\n%s\n", node, docs)
		}

		return nil
	}

	cl, nctx, err := c.node(ctx, node, "patch")
	if err != nil {
		return err
	}

	body, err := c.machineConfig(nctx, cl)
	if err != nil {
		return err
	}

	var ps []configpatcher.Patch

	for i, docs := range patches {
		p, err := configpatcher.LoadPatch(docs)
		if err != nil {
			return fmt.Errorf("patch %d for %s: %w", i, node, err)
		}

		ps = append(ps, p)
	}

	out, err := configpatcher.Apply(configpatcher.WithBytes(body), ps)
	if err != nil {
		return fmt.Errorf("patching the config of %s: %w", node, err)
	}

	data, err := out.Bytes()
	if err != nil {
		return err
	}

	// the last moment before anything reaches the node
	if until, ok := ctx.Value(applyBeforeKey{}).(time.Time); ok && !time.Now().Before(until) {
		return ErrApplyDeadline
	}

	resp, err := cl.ApplyConfiguration(nctx, &machine.ApplyConfigurationRequest{
		Data: data,
		Mode: machine.ApplyConfigurationRequest_NO_REBOOT,
	})
	if err != nil {
		return wrap("apply config on "+node, err)
	}

	for _, m := range resp.GetMessages() {
		if e := m.GetMetadata().GetError(); e != "" {
			return fmt.Errorf("apply config on %s: %s", node, e)
		}
	}

	return nil
}

// MachineConfig returns the node's active machine config (all documents, YAML).
func (c *Client) MachineConfig(ctx context.Context, node string) (string, error) {
	cl, nctx, err := c.node(ctx, node, "get machineconfig")
	if err != nil {
		return "", err
	}

	body, err := c.machineConfig(nctx, cl)

	return string(body), err
}

// machineConfig reads the raw active config, the same way talosctl patch does:
// the resource spec is the config as a YAML string.
func (c *Client) machineConfig(ctx context.Context, cl *client.Client) ([]byte, error) {
	mc, err := cl.COSI.Get(ctx, resource.NewMetadata(config.NamespaceName, config.MachineConfigType, config.ActiveID, resource.VersionUndefined))
	if err != nil {
		return nil, wrap("get machineconfig", err)
	}

	if mc.Metadata().Annotations().Empty() {
		// older Talos marshaled the spec as a YAML document, which loses all but the first document
		if pb, ok := mc.(*protobuf.Resource); ok {
			p, err := pb.Marshal()
			if err != nil {
				return nil, err
			}

			return []byte(p.GetSpec().GetYamlSpec()), nil
		}

		return yaml.Marshal(mc.Spec())
	}

	spec, err := yaml.Marshal(mc.Spec())
	if err != nil {
		return nil, err
	}

	var body string
	if err := yaml.Unmarshal(spec, &body); err != nil {
		return nil, err
	}

	return []byte(body), nil
}

// ContainerStatuses returns the status of every ContainerConfig container on a node, keyed by name.
func (c *Client) ContainerStatuses(ctx context.Context, node string) (map[string]containers.ContainerStatusSpec, error) {
	if c.DryRun {
		return map[string]containers.ContainerStatusSpec{}, nil
	}

	cl, nctx, err := c.node(ctx, node, "get containerstatus")
	if err != nil {
		return nil, err
	}

	list, err := safe.StateListAll[*containers.ContainerStatus](nctx, cl.COSI)
	if err != nil {
		return nil, wrap("list containerstatus on "+node, err)
	}

	res := map[string]containers.ContainerStatusSpec{}

	for r := range list.All() {
		res[r.Metadata().ID()] = *r.TypedSpec()
	}

	return res, nil
}

// ImageStatus returns the image pull status of a ContainerConfig container
// (a ContainerImageStatus has the same ID as its container).
func (c *Client) ImageStatus(ctx context.Context, node, name string) (containers.ContainerImageStatusSpec, error) {
	cl, nctx, err := c.node(ctx, node, "get containerimagestatus "+name)
	if err != nil {
		return containers.ContainerImageStatusSpec{}, err
	}

	r, err := safe.StateGetByID[*containers.ContainerImageStatus](nctx, cl.COSI, name)
	if err != nil {
		return containers.ContainerImageStatusSpec{}, wrap("get containerimagestatus "+name+" on "+node, err)
	}

	return *r.TypedSpec(), nil
}

// ImageStatuses returns the image pull status of every ContainerConfig container, keyed by name.
func (c *Client) ImageStatuses(ctx context.Context, node string) (map[string]containers.ContainerImageStatusSpec, error) {
	cl, nctx, err := c.node(ctx, node, "get containerimagestatus")
	if err != nil {
		return nil, err
	}

	list, err := safe.StateListAll[*containers.ContainerImageStatus](nctx, cl.COSI)
	if err != nil {
		return nil, wrap("list containerimagestatus on "+node, err)
	}

	res := map[string]containers.ContainerImageStatusSpec{}

	for r := range list.All() {
		res[r.Metadata().ID()] = *r.TypedSpec()
	}

	return res, nil
}

// instanceGenerations returns the generations of all ContainerInstanceSpecs of a
// container. The spec holds a finalizer until the process is gone, so it is the
// lifecycle the CLI waits on; it is sensitive (the environment), so this needs os:admin.
func (c *Client) instanceGenerations(ctx context.Context, node, name string) ([]uint64, error) {
	cl, nctx, err := c.node(ctx, node, "get containerinstancespec")
	if err != nil {
		return nil, err
	}

	list, err := safe.StateListAll[*containers.ContainerInstanceSpec](nctx, cl.COSI)
	if err != nil {
		return nil, wrap("list containerinstancespec on "+node, err)
	}

	var gens []uint64

	for r := range list.All() {
		if r.TypedSpec().ContainerID == name {
			gens = append(gens, r.TypedSpec().Generation)
		}
	}

	return gens, nil
}

// InstanceContainers returns the containers that still have an instance, from
// ContainerInstanceStatus, which os:reader may list. It is informational: the
// status appears only after the task started, so lifecycle waits use the spec.
func (c *Client) InstanceContainers(ctx context.Context, node string) ([]string, error) {
	cl, nctx, err := c.node(ctx, node, "get containerinstancestatus")
	if err != nil {
		return nil, err
	}

	list, err := safe.StateListAll[*containers.ContainerInstanceStatus](nctx, cl.COSI)
	if err != nil {
		return nil, wrap("list containerinstancestatus on "+node, err)
	}

	var out []string

	for r := range list.All() {
		if id := r.TypedSpec().ContainerID; !slices.Contains(out, id) {
			out = append(out, id)
		}
	}

	return out, nil
}

// HasInstances reports whether any ContainerInstanceSpec of a container is left.
// Instances keep a finalizer until their process is gone, unlike ContainerStatus
// which disappears as soon as the ContainerConfig is deleted.
func (c *Client) HasInstances(ctx context.Context, node, name string) (bool, error) {
	gens, err := c.instanceGenerations(ctx, node, name)

	return len(gens) > 0, err
}

// InstanceGeneration returns the highest ContainerInstanceSpec generation of a
// container; Talos creates a new generation whenever it replaces the instance.
func (c *Client) InstanceGeneration(ctx context.Context, node, name string) (uint64, error) {
	gens, err := c.instanceGenerations(ctx, node, name)

	var gen uint64

	for _, g := range gens {
		gen = max(gen, g)
	}

	return gen, err
}

// recheck is how often WaitFor re-runs its check without an event.
var recheck = 10 * time.Second

// Permanent returns err if retrying cannot help (permission denied, not
// authenticated), and nil for errors a later check may not hit again.
func Permanent(err error) error {
	// status.Code also finds a status wrapped by fmt.Errorf
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		return err
	}

	return nil
}

// Watched resource types for WaitFor.
var (
	StatusTypes   = []resource.Type{containers.ContainerStatusType}
	ImageTypes    = []resource.Type{containers.ContainerStatusType, containers.ContainerImageStatusType}
	InstanceTypes = []resource.Type{containers.ContainerStatusType, containers.ContainerInstanceSpecType}
)

// WaitFor calls check once, then again whenever a resource of one of the types
// changes on the node, until check reports done, returns an error, or the
// timeout passes. A broken watch is re-established (and check re-run) after a
// short pause, so a node that is briefly unreachable does not end the wait.
func (c *Client) WaitFor(ctx context.Context, node string, types []resource.Type, timeout time.Duration, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		done, err := c.watchOnce(ctx, node, types, check)
		if done || err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// watchOnce runs one watch session; it returns (false, nil) when the watch breaks.
func (c *Client) watchOnce(ctx context.Context, node string, types []resource.Type, check func(context.Context) (bool, error)) (bool, error) {
	cl, nctx, err := c.node(ctx, node, "watch")
	if err != nil {
		return false, err
	}

	wctx, cancel := context.WithCancel(nctx)
	defer cancel()

	ch := make(chan state.Event)

	for _, t := range types {
		md := resource.NewMetadata(containers.NamespaceName, t, "", resource.VersionUndefined)
		if err := cl.COSI.WatchKind(wctx, md, ch); err != nil {
			return false, Permanent(err) // anything else is retried by WaitFor
		}
	}

	// the watches are in place: anything that changes from now on triggers a re-check
	if done, err := check(ctx); done || err != nil {
		return done, err
	}

	// a check that failed on a transient read error is retried after a while,
	// also when nothing changes anymore
	tick := time.NewTicker(recheck)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case ev := <-ch:
			if ev.Type == state.Errored {
				return false, Permanent(ev.Error)
			}
		case <-tick.C:
		}

		if done, err := check(ctx); done || err != nil {
			return done, err
		}
	}
}

// ReadFile reads a file on the node through the Talos API, at most limit bytes;
// a missing file is fs.ErrNotExist.
func (c *Client) ReadFile(ctx context.Context, node, path string, limit int64) ([]byte, error) {
	cl, nctx, err := c.node(ctx, node, "read "+path)
	if err != nil {
		return nil, err
	}

	r, err := cl.Read(nctx, path)
	if err != nil {
		return nil, wrap("read "+path, err)
	}

	defer r.Close() //nolint:errcheck

	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		if status.Code(err) == codes.NotFound || strings.Contains(err.Error(), "no such file") {
			return nil, fs.ErrNotExist
		}

		return nil, wrap("read "+path, err)
	}

	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}

	return b, nil
}

// Logs returns the full log of a ContainerConfig container.
func (c *Client) Logs(ctx context.Context, node, name string) (string, error) {
	if c.DryRun {
		return "", nil
	}

	var b strings.Builder

	err := c.streamLogs(ctx, node, name, false, &b)

	return b.String(), err
}

// FollowLogs streams the log of a container to w until ctx is done.
func (c *Client) FollowLogs(ctx context.Context, node, name string, w io.Writer) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# follow the log of %s on %s\n", name, node)

		return nil
	}

	return c.streamLogs(ctx, node, name, true, w)
}

func (c *Client) streamLogs(ctx context.Context, node, name string, follow bool, w io.Writer) error {
	cl, nctx, err := c.node(ctx, node, "logs "+name)
	if err != nil {
		return err
	}

	stream, err := cl.Logs(nctx, Namespace, common.ContainerDriver_CONTAINERD, name, follow, -1)
	if err != nil {
		return wrap("logs "+name+" on "+node, err)
	}

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) || (err != nil && ctx.Err() != nil && follow) {
			return nil
		}

		if err != nil {
			return wrap("logs "+name+" on "+node, err)
		}

		if e := msg.GetMetadata().GetError(); e != "" {
			return fmt.Errorf("logs %s on %s: %s", name, node, e)
		}

		if _, err := w.Write(msg.GetBytes()); err != nil {
			return err
		}
	}
}

// Exec runs a command in a running container (Talos ContainerExec) and returns its
// exit code. Secrets go through stdin only: Talos audits the arguments.
func (c *Client) Exec(ctx context.Context, node, container string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cl, nctx, err := c.node(ctx, node, "exec "+container)
	if err != nil {
		return 0, err
	}

	res, err := cl.ContainerExec(nctx, &machine.DebugContainerExecRequestSpec{Container: container, Args: args},
		client.ContainerStreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr})
	if err != nil {
		if execNotStarted(err) {
			return 0, fmt.Errorf("exec in %s: %w: %w", container, ErrExecNotStarted, err)
		}

		return 0, wrap("exec in "+container, err)
	}

	return res.ExitCode, nil
}

// execNotStarted reports whether a ContainerExec error came before the command
// started: Talos reports a container that is not (or no longer) running as
// FailedPrecondition, or, when its init process stops during the setup, as
// "failed to exec in container" with containerd's reason.
func execNotStarted(err error) bool {
	return status.Code(err) == codes.FailedPrecondition || strings.Contains(err.Error(), "failed to exec in container")
}

// Restart restarts a ContainerConfig container.
func (c *Client) Restart(ctx context.Context, node, name string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# restart %s on %s\n", name, node)

		return nil
	}

	id, err := c.Instance(ctx, node, name)
	if err != nil {
		return err
	}

	return c.RestartInstance(ctx, node, id)
}

// Instance returns the current instance of a ContainerConfig container: the
// ContainerInstanceSpec ID with the highest generation (e.g. <name>-3), by
// which containerd knows it.
func (c *Client) Instance(ctx context.Context, node, name string) (string, error) {
	cl, nctx, err := c.node(ctx, node, "get instances of "+name)
	if err != nil {
		return "", err
	}

	list, err := safe.StateListAll[*containers.ContainerInstanceSpec](nctx, cl.COSI)
	if err != nil {
		return "", wrap("list containerinstancespec on "+node, err)
	}

	var (
		id  string
		gen uint64
	)

	for r := range list.All() {
		if s := r.TypedSpec(); s.ContainerID == name && (id == "" || s.Generation > gen) {
			id, gen = r.Metadata().ID(), s.Generation
		}
	}

	if id == "" {
		return "", fmt.Errorf("%s on %s: %w: no running instance", name, node, ErrNotFound)
	}

	return id, nil
}

// InstanceOwners returns the ContainerConfig containers that have an instance
// on node, running or not yet cleaned up.
func (c *Client) InstanceOwners(ctx context.Context, node string) ([]string, error) {
	cl, nctx, err := c.node(ctx, node, "list instances")
	if err != nil {
		return nil, err
	}

	list, err := safe.StateListAll[*containers.ContainerInstanceSpec](nctx, cl.COSI)
	if err != nil {
		return nil, wrap("list containerinstancespec on "+node, err)
	}

	seen := map[string]bool{}

	var out []string

	for r := range list.All() {
		if id := r.TypedSpec().ContainerID; !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}

	sort.Strings(out)

	return out, nil
}

// RestartInstance restarts one instance (Instance) of a ContainerConfig
// container: Talos stops it within its stop timeout and starts the next one.
func (c *Client) RestartInstance(ctx context.Context, node, id string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# restart %s on %s\n", id, node)

		return nil
	}

	cl, nctx, err := c.node(ctx, node, "restart "+id)
	if err != nil {
		return err
	}

	return wrap("restart "+id+" on "+node, cl.Restart(nctx, Namespace, common.ContainerDriver_CONTAINERD, id))
}

// EtcFileWritten reports whether a file below /etc (EtcFileConfig name, e.g.
// ceph/ceph.conf) has the contents on disk: Talos writes files after it
// accepted the config, and records the spec version it wrote in EtcFileStatus.
func (c *Client) EtcFileWritten(ctx context.Context, node, name, contents string) (bool, error) {
	cl, nctx, err := c.node(ctx, node, "get etcfile "+name)
	if err != nil {
		return false, err
	}

	spec, err := safe.StateGetByID[*files.EtcFileSpec](nctx, cl.COSI, name)
	if state.IsNotFoundError(err) {
		return false, nil
	}

	if err != nil {
		return false, wrap("get etcfilespec "+name+" on "+node, err)
	}

	if string(spec.TypedSpec().Contents) != contents {
		return false, nil
	}

	st, err := safe.StateGetByID[*files.EtcFileStatus](nctx, cl.COSI, name)
	if state.IsNotFoundError(err) {
		return false, nil
	}

	if err != nil {
		return false, wrap("get etcfilestatus "+name+" on "+node, err)
	}

	return st.TypedSpec().SpecVersion == spec.Metadata().Version().String(), nil
}

// RebootTimeout bounds how long Reboot waits for the node to be back.
const RebootTimeout = 20 * time.Minute

// rebootPoll is how often Reboot checks whether the node is back.
var rebootPoll = 5 * time.Second

// Reboot reboots a node and waits until it is back: a new boot id, and the
// machine in stage running and ready (like `talosctl reboot --wait`).
func (c *Client) Reboot(ctx context.Context, node string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# reboot %s\n", node)

		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, RebootTimeout)
	defer cancel()

	cl, nctx, err := c.node(ctx, node, "reboot")
	if err != nil {
		return err
	}

	before, err := safe.StateGetByID[*runtime.BootID](nctx, cl.COSI, runtime.BootIDID)
	if err != nil {
		return wrap("get boot id of "+node, err)
	}

	if err := cl.Reboot(nctx); err != nil {
		return wrap("reboot "+node, err)
	}

	return c.waitBooted(ctx, node, before.TypedSpec().BootID, RebootTimeout, rebootPoll)
}

// waitBooted waits for a boot id other than old and a running, ready machine.
func (c *Client) waitBooted(ctx context.Context, node, old string, timeout, every time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	last := "node unreachable"

	for {
		if ok, why := c.booted(ctx, node, old); ok {
			return nil
		} else if why != "" {
			last = why
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s to come back from the reboot (%s): %w", node, last, ctx.Err())
		case <-time.After(every):
		}
	}
}

func (c *Client) booted(ctx context.Context, node, old string) (bool, string) {
	cl, nctx, err := c.node(ctx, node, "get bootid,machinestatus")
	if err != nil {
		return false, err.Error()
	}

	// short calls: the node goes away during the reboot
	nctx, cancel := context.WithTimeout(nctx, 10*time.Second)
	defer cancel()

	id, err := safe.StateGetByID[*runtime.BootID](nctx, cl.COSI, runtime.BootIDID)
	if err != nil {
		return false, ""
	}

	if id.TypedSpec().BootID == old {
		return false, "not rebooted yet"
	}

	ms, err := safe.StateGetByID[*runtime.MachineStatus](nctx, cl.COSI, runtime.MachineStatusID)
	if err != nil {
		return false, ""
	}

	s := ms.TypedSpec()
	if s.Stage != runtime.MachineStageRunning || !s.Status.Ready {
		return false, fmt.Sprintf("stage %s, ready %t", s.Stage, s.Status.Ready)
	}

	return true, ""
}

// BootID returns the boot id of a node; it changes with every boot.
func (c *Client) BootID(ctx context.Context, node string) (string, error) {
	cl, nctx, err := c.node(ctx, node, "get bootid")
	if err != nil {
		return "", err
	}

	r, err := safe.StateGetByID[*runtime.BootID](nctx, cl.COSI, runtime.BootIDID)
	if err != nil {
		return "", wrap("get boot id of "+node, err)
	}

	return r.TypedSpec().BootID, nil
}

// Hostname returns the Talos hostname of a node.
func (c *Client) Hostname(ctx context.Context, node string) (string, error) {
	cl, nctx, err := c.node(ctx, node, "get hostnamestatus")
	if err != nil {
		return "", err
	}

	r, err := safe.StateGetByID[*network.HostnameStatus](nctx, cl.COSI, network.HostnameID)
	if err != nil {
		return "", wrap("get hostname of "+node, err)
	}

	return r.TypedSpec().Hostname, nil
}

// Version returns the Talos server version tag of a node.
func (c *Client) Version(ctx context.Context, node string) (string, error) {
	cl, nctx, err := c.node(ctx, node, "version")
	if err != nil {
		return "", err
	}

	resp, err := cl.Version(nctx)
	if err != nil {
		return "", wrap("version of "+node, err)
	}

	for _, m := range resp.GetMessages() {
		if e := m.GetMetadata().GetError(); e != "" {
			return "", fmt.Errorf("version of %s: %s", node, e)
		}

		return m.GetVersion().GetTag(), nil
	}

	return "", fmt.Errorf("version of %s: empty response", node)
}

// Upgrade starts a Talos upgrade of a node to the given installer image.
// The node reboots when it is done; Upgrade does not wait for that.
func (c *Client) Upgrade(ctx context.Context, node, installer string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# upgrade %s to %s\n", node, installer)

		return nil
	}

	cl, nctx, err := c.node(ctx, node, "upgrade")
	if err != nil {
		return err
	}

	resp, err := cl.UpgradeWithOptions(nctx, client.WithUpgradeImage(installer))
	if err != nil {
		return wrap("upgrade "+node, err)
	}

	for _, m := range resp.GetMessages() {
		if e := m.GetMetadata().GetError(); e != "" {
			return fmt.Errorf("upgrade %s: %s", node, e)
		}
	}

	return nil
}

// Disks returns the block devices of a node (block.Disk resources), sorted by ID.
func (c *Client) Disks(ctx context.Context, node string) ([]*block.Disk, error) {
	cl, nctx, err := c.node(ctx, node, "get disks")
	if err != nil {
		return nil, err
	}

	list, err := safe.StateListAll[*block.Disk](nctx, cl.COSI)
	if err != nil {
		return nil, wrap("list disks on "+node, err)
	}

	out := slices.Collect(list.All())
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata().ID() < out[j].Metadata().ID() })

	return out, nil
}

// PullImage pulls an image into the ContainerConfig namespace of a node and
// returns its canonical name@digest reference. Talos skips images it already
// has, so a floating tag resolves to whatever the node pulled first; refresh
// removes the node's copy of the reference before pulling.
func (c *Client) PullImage(ctx context.Context, node, ref string, refresh bool) (string, error) {
	cl, nctx, err := c.node(ctx, node, "pull "+ref)
	if err != nil {
		return "", err
	}

	ns := &common.ContainerdInstance{Driver: common.ContainerDriver_CONTAINERD, Namespace: common.ContainerdNamespace_NS_TALOSCONTAINERS}

	if refresh {
		// Talos stores images under their normalized name (ceph/ceph:v20 is docker.io/ceph/ceph:v20)
		named, err := reference.ParseDockerRef(ref)
		if err != nil {
			return "", fmt.Errorf("image reference %q: %w", ref, err)
		}

		if _, err := cl.ImageClient.Remove(nctx, &machine.ImageServiceRemoveRequest{Containerd: ns, ImageRef: named.String()}); err != nil && status.Code(err) != codes.NotFound {
			return "", wrap("remove "+ref+" on "+node, err)
		}
	}

	stream, err := cl.ImageClient.Pull(nctx, &machine.ImageServicePullRequest{Containerd: ns, ImageRef: ref})
	if err != nil {
		return "", wrap("pull "+ref+" on "+node, err)
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return "", wrap("pull "+ref+" on "+node, err)
		}

		if name := msg.GetName(); name != "" {
			return name, nil
		}
	}
}
