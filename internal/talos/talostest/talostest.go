// Package talostest is an in-process fake Talos node for tests: the COSI state
// service backed by an in-memory state, and the parts of the machine and image
// services cephadm-talos uses.
package talostest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"net"
	"path/filepath"
	"sync"
	"testing"

	cosiv1alpha1 "github.com/cosi-project/runtime/api/v1alpha1"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/cosi-project/runtime/pkg/state/impl/inmem"
	"github.com/cosi-project/runtime/pkg/state/impl/namespaced"
	"github.com/cosi-project/runtime/pkg/state/protobuf/server"
	"github.com/distribution/reference"
	"github.com/siderolabs/talos/pkg/machinery/api/common"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/config/configloader"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Node is an in-process Talos node: the COSI state service backed by an
// in-memory state, and the parts of the machine service the client uses.
type Node struct {
	machine.UnimplementedMachineServiceServer

	St      state.State
	Sock    string
	Mu      sync.Mutex
	Applied [][]byte
	Reboots int
	Srv     *grpc.Server
	OnBoot  func() // called by Reboot, after the boot id changed
	Images  machine.ImageServiceServer
	// Restarted lists the containers Restart was called for
	Restarted []string
	// HoldRestarts keeps restarted instances from being replaced (a daemon
	// still stopping)
	HoldRestarts bool
	// ContainerLogs is what Logs streams for a container (two lines otherwise)
	ContainerLogs map[string]string
	// VersionTag is what Version reports (default v1.15.0-alpha.2)
	VersionTag string
	// Files is what Read serves by path (CPUInfo for /proc/cpuinfo when
	// unset); any other path is unimplemented, as before Read existed
	Files map[string]string
	// FailBeforeApply makes the next ApplyConfiguration fail without storing
	// the config, like a connection lost before the node got it
	FailBeforeApply error
	// FailAfterApply makes the next ApplyConfiguration store the config and
	// then fail, like a connection lost after the node accepted it
	FailAfterApply error

	// the machine events published (PublishSequence) and the streams that follow them
	evMu    sync.Mutex
	events  []*machine.Event
	evWatch []chan *machine.Event
}

const baseConfig = `version: v1alpha1
machine:
  type: controlplane
  token: abc
  ca:
    crt: ""
    key: ""
cluster:
  controlPlane:
    endpoint: https://10.5.0.2:6443
---
apiVersion: v1alpha1
kind: EtcFileConfig
name: ceph/ceph.conf
contents: |
  [global]
---
apiVersion: v1alpha1
kind: ContainerConfig
name: app
image: docker.io/library/alpine:3
environment:
  - A=1
`

// New starts a fake node with a base config, a boot id and a ready machine.
func New(t *testing.T, images ...machine.ImageServiceServer) *Node {
	t.Helper()

	f := &Node{
		St:   state.WrapCore(namespaced.NewState(inmem.Build)),
		Sock: filepath.Join(t.TempDir(), "talos.sock"),
	}

	if len(images) > 0 {
		f.Images = images[0]
	}

	ctx := context.Background()

	f.SetConfig(t, []byte(baseConfig))

	id := runtime.NewBootID()
	id.TypedSpec().BootID = "boot-1"
	must(t, f.St.Create(ctx, id))

	ms := runtime.NewMachineStatus()
	ms.TypedSpec().Stage = runtime.MachineStageRunning
	ms.TypedSpec().Status.Ready = true
	must(t, f.St.Create(ctx, ms))

	f.Serve(t)

	return f
}

func (f *Node) Serve(t *testing.T) {
	t.Helper()

	l, err := net.Listen("unix", f.Sock)
	if err != nil {
		t.Fatal(err)
	}

	f.Srv = grpc.NewServer()
	cosiv1alpha1.RegisterStateServer(f.Srv, server.NewState(f.St))
	machine.RegisterMachineServiceServer(f.Srv, f)

	if f.Images != nil {
		machine.RegisterImageServiceServer(f.Srv, f.Images)
	}

	go f.Srv.Serve(l) //nolint:errcheck

	t.Cleanup(f.Srv.Stop)
}

func (f *Node) SetConfig(t *testing.T, data []byte) {
	t.Helper()

	p, err := configloader.NewFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	mc := config.NewMachineConfig(p)

	if _, err := f.St.Get(ctx, mc.Metadata()); err == nil {
		cur, _ := f.St.Get(ctx, mc.Metadata())
		mc.Metadata().SetVersion(cur.Metadata().Version())
		must(t, f.St.Update(ctx, mc))

		return
	}

	must(t, f.St.Create(ctx, mc))
}

func (f *Node) ApplyConfiguration(_ context.Context, req *machine.ApplyConfigurationRequest) (*machine.ApplyConfigurationResponse, error) {
	if req.Mode != machine.ApplyConfigurationRequest_NO_REBOOT {
		return nil, errors.New("want NO_REBOOT")
	}

	f.Mu.Lock()
	before := f.FailBeforeApply
	f.FailBeforeApply = nil
	f.Mu.Unlock()

	if before != nil {
		return nil, before
	}

	if bytes.Contains(req.Data, []byte("name: rejected")) {
		return nil, status.Error(codes.InvalidArgument, "config validation failed")
	}

	p, err := configloader.NewFromBytes(req.Data)
	if err != nil {
		return nil, err
	}

	// as machined validates: a dependency must name a configured container
	names := map[string]bool{}
	for _, c := range p.ContainerConfigs() {
		names[c.Name()] = true
	}

	for _, c := range p.ContainerConfigs() {
		for _, dep := range c.DependsOn().Containers() {
			if !names[dep.Name()] {
				return nil, status.Errorf(codes.InvalidArgument, "container %q depends on container %q, which is not configured", c.Name(), dep.Name())
			}
		}
	}

	f.Mu.Lock()
	f.Applied = append(f.Applied, req.Data)
	f.Mu.Unlock()

	ctx := context.Background()
	mc := config.NewMachineConfig(p)
	cur, err := f.St.Get(ctx, mc.Metadata())

	if err != nil {
		return nil, err
	}

	mc.Metadata().SetVersion(cur.Metadata().Version())

	if err := f.St.Update(ctx, mc); err != nil {
		return nil, err
	}

	f.Mu.Lock()
	fail := f.FailAfterApply
	f.FailAfterApply = nil
	f.Mu.Unlock()

	if fail != nil {
		return nil, fail
	}

	return &machine.ApplyConfigurationResponse{Messages: []*machine.ApplyConfiguration{{}}}, nil
}

func (f *Node) Reboot(context.Context, *machine.RebootRequest) (*machine.RebootResponse, error) {
	f.Mu.Lock()
	f.Reboots++
	f.Mu.Unlock()

	ctx := context.Background()

	ms := runtime.NewMachineStatus()
	cur, _ := f.St.Get(ctx, ms.Metadata())
	ms.Metadata().SetVersion(cur.Metadata().Version())
	ms.TypedSpec().Stage = runtime.MachineStageBooting
	ms.TypedSpec().Status.Ready = false

	if err := f.St.Update(ctx, ms); err != nil {
		return nil, err
	}

	id := runtime.NewBootID()
	cur, _ = f.St.Get(ctx, id.Metadata())
	id.Metadata().SetVersion(cur.Metadata().Version())
	id.TypedSpec().BootID = "boot-2"

	if err := f.St.Update(ctx, id); err != nil {
		return nil, err
	}

	if f.OnBoot != nil {
		go f.OnBoot()
	}

	return &machine.RebootResponse{}, nil
}

func (f *Node) Version(context.Context, *emptypb.Empty) (*machine.VersionResponse, error) {
	tag := f.VersionTag
	if tag == "" {
		tag = "v1.15.0-alpha.2"
	}

	return &machine.VersionResponse{Messages: []*machine.Version{{Version: &machine.VersionInfo{Tag: tag}}}}, nil
}

// Restart records the instance and, like Talos once the instance stopped,
// starts the next one (unless HoldRestarts): a ContainerInstanceSpec with the
// next generation.
func (f *Node) Restart(ctx context.Context, req *machine.RestartRequest) (*machine.RestartResponse, error) {
	f.Mu.Lock()
	f.Restarted = append(f.Restarted, req.Id)
	hold := f.HoldRestarts
	f.Mu.Unlock()

	if hold {
		return &machine.RestartResponse{}, nil
	}

	cur, err := safe.StateGetByID[*containers.ContainerInstanceSpec](ctx, f.St, req.Id)
	if err != nil {
		return &machine.RestartResponse{}, nil //nolint:nilerr // not an instance this fake knows
	}

	gen := cur.TypedSpec().Generation + 1
	next := containers.NewContainerInstanceSpec(containers.NamespaceName, fmt.Sprintf("%s-%d", cur.TypedSpec().ContainerID, gen))
	next.TypedSpec().ContainerID, next.TypedSpec().Generation = cur.TypedSpec().ContainerID, gen

	return &machine.RestartResponse{}, f.St.Create(ctx, next)
}

// CPUInfo is a /proc/cpuinfo whose CPU supports x86-64-v3.
const CPUInfo = "processor\t: 0\nflags\t\t: fpu sse sse2 ssse3 cx16 sse4_1 sse4_2 popcnt lahf_lm movbe xsave avx f16c fma abm avx2 bmi1 bmi2\n\n"

// Read serves Files.
func (f *Node) Read(req *machine.ReadRequest, srv machine.MachineService_ReadServer) error {
	f.Mu.Lock()
	body, ok := f.Files[req.Path]
	if !ok && req.Path == "/proc/cpuinfo" && f.Files == nil {
		body, ok = CPUInfo, true
	}
	f.Mu.Unlock()

	if !ok {
		return status.Error(codes.Unimplemented, "read "+req.Path)
	}

	return srv.Send(&common.Data{Bytes: []byte(body)})
}

func (f *Node) Logs(req *machine.LogsRequest, srv machine.MachineService_LogsServer) error {
	if req.Namespace != "taloscontainers" || req.Driver != common.ContainerDriver_CONTAINERD {
		return errors.New("wrong namespace or driver")
	}

	f.Mu.Lock()
	logs, set := f.ContainerLogs[req.Id]
	f.Mu.Unlock()

	if set {
		return srv.Send(&common.Data{Bytes: []byte(logs)})
	}

	for _, chunk := range []string{"line 1\n", "line 2\n"} {
		if err := srv.Send(&common.Data{Bytes: []byte(chunk)}); err != nil {
			return err
		}
	}

	return nil
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// ImageService is the image service of a fake node: a cache keyed by the
// normalized name, which Pull skips like Talos does.
type ImageService struct {
	machine.UnimplementedImageServiceServer

	mu      sync.Mutex
	Cache   map[string]string // normalized name -> digest
	Remote  map[string]string // what the registry has now
	Removed []string
}

func (f *ImageService) Remove(_ context.Context, req *machine.ImageServiceRemoveRequest) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Removed = append(f.Removed, req.ImageRef)

	if _, ok := f.Cache[req.ImageRef]; !ok {
		return nil, status.Error(codes.NotFound, "no such image")
	}

	delete(f.Cache, req.ImageRef)

	return &emptypb.Empty{}, nil
}

func (f *ImageService) Pull(req *machine.ImageServicePullRequest, srv machine.ImageService_PullServer) error {
	named, err := reference.ParseDockerRef(req.ImageRef)
	if err != nil {
		return err
	}

	f.mu.Lock()
	d, ok := f.Cache[named.String()]
	if !ok {
		d = f.Remote[named.String()]
		f.Cache[named.String()] = d
	}
	f.mu.Unlock()

	return srv.Send(&machine.ImageServicePullResponse{Response: &machine.ImageServicePullResponse_Name{Name: named.Name() + "@" + d}})
}

// PublishSequence publishes a sequence event, as machined does when a
// sequence starts, stops or ends without running (code nil: no error).
func (f *Node) PublishSequence(seq string, action machine.SequenceEvent_Action, code *common.Code) {
	ev := &machine.SequenceEvent{Sequence: seq, Action: action}
	if code != nil {
		ev.Error = &common.Error{Code: *code, Message: "sequence failed"}
	}

	raw, err := proto.Marshal(ev)
	if err != nil {
		panic(err)
	}

	f.evMu.Lock()
	defer f.evMu.Unlock()

	e := &machine.Event{Id: fmt.Sprintf("%020d", len(f.events)+1), Data: &anypb.Any{TypeUrl: "talos/runtime/machine.SequenceEvent", Value: raw}}
	f.events = append(f.events, e)

	for _, ch := range f.evWatch {
		ch <- e
	}
}

// Events streams an empty event, then the events after the request's tail
// id (none before it without one), then every one published.
func (f *Node) Events(req *machine.EventsRequest, srv machine.MachineService_EventsServer) error {
	if err := srv.Send(&machine.Event{}); err != nil {
		return err
	}

	ch := make(chan *machine.Event, 64)

	f.evMu.Lock()

	var past []*machine.Event

	if req.GetTailId() != "" {
		for _, e := range f.events {
			if e.Id > req.GetTailId() {
				past = append(past, e)
			}
		}
	}

	f.evWatch = append(f.evWatch, ch)
	f.evMu.Unlock()

	defer func() {
		f.evMu.Lock()
		defer f.evMu.Unlock()

		for i, c := range f.evWatch {
			if c == ch {
				f.evWatch = append(f.evWatch[:i], f.evWatch[i+1:]...)

				break
			}
		}
	}()

	for _, e := range past {
		if err := srv.Send(e); err != nil {
			return err
		}
	}

	for {
		select {
		case <-srv.Context().Done():
			return nil
		case e := <-ch:
			if err := srv.Send(e); err != nil {
				return err
			}
		}
	}
}

// SetStage sets the machine's stage, as machined does when a sequence starts.
func (f *Node) SetStage(t *testing.T, stage runtime.MachineStage) {
	t.Helper()

	ctx := context.Background()
	ms := runtime.NewMachineStatus()
	cur, err := f.St.Get(ctx, ms.Metadata())
	must(t, err)

	ms.Metadata().SetVersion(cur.Metadata().Version())
	ms.TypedSpec().Stage = stage
	must(t, f.St.Update(ctx, ms))
}

// Dial returns a Talos client connected to the node.
func (f *Node) Dial(ctx context.Context) (*client.Client, error) {
	return client.New(ctx, client.WithUnixSocket(f.Sock), client.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())))
}
