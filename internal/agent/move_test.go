package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/block"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"

	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// nodeAddr gives the fake node of h1 an address.
func nodeAddr(t *testing.T, s *leaderSetup, prefix string) {
	t.Helper()

	p := netip.MustParsePrefix(prefix)
	a := network.NewAddressStatus(network.NamespaceName, "eth0/"+prefix)
	a.TypedSpec().Address = p
	must(t, s.agent.fake.St.Create(context.Background(), a))
}

// acceptMove accepts set_host_addr of h1 to addr.
func (s *leaderSetup) acceptMove(addr string, seq int64) LedgerEntry {
	s.accept(KindSetAddr, "", "h1", seq)

	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	s.module.ledger[len(s.module.ledger)-1].Op.Addr = addr

	return s.module.ledger[len(s.module.ledger)-1]
}

func (s *leaderSetup) move(t *testing.T) *state.Move {
	t.Helper()

	return s.host(t, "h1").Move
}

// moveSetup is a leader whose h1 has its agent's documents, a mon, an OSD and
// the mgr (added through the ledger, the active one), its node holding
// 10.5.0.3 and 10.5.0.9.
func moveSetup(t *testing.T) (*leaderSetup, state.Host) {
	t.Helper()

	s, h := agentSetup(t)
	ctx := context.Background()

	nodeAddr(t, s, "10.5.0.3/24")
	nodeAddr(t, s, "10.5.0.9/24")

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, s.agent.fake.St.Create(ctx, disk))

	id := 3
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", OSDID: &id, OSDUUID: "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f", DeployID: "0123456789abcdef",
			DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"})
		st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})

		h0, _ := st.Host("h0")
		h0.Maintenance = true // ceph.conf goes to h1 alone (this test serves h1's agent only)
		st.AddHost(h0)

		return nil
	}))

	s.module.mu.Lock()
	s.module.active, s.module.standbys, s.module.quorum = "h0", []string{"h1"}, []string{"h0", "h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	s.module.mu.Lock()
	s.module.retired = nil
	s.module.active, s.module.standbys = "h1", nil // the mgr on h1 is the active one
	s.module.mu.Unlock()

	// the agent serves its new certificates as soon as they are granted
	s.leader.serves = func(string, int, string) bool { return true }

	return s, h
}

func TestAMoveMovesEachDaemonInItsOwnStep(t *testing.T) {
	s, before := moveSetup(t)
	ctx := context.Background()

	mv := s.acceptMove("10.5.0.9", 2)
	op := mv.Op.ID

	must(t, s.leader.Tick(ctx, 42, 5))

	// recorded, confirmed at the new address: the contact address switched,
	// every daemon still on the old one
	m := s.move(t)
	if m == nil || m.Op != op || m.From != "10.5.0.3" || m.To != "10.5.0.9" || !slices.Contains(m.Done, moveConfirm) {
		t.Fatalf("record %+v", m)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if h, _ := st.Host("h1"); h.Addr != "10.5.0.9" {
		t.Fatalf("addr %s", h.Addr)
	}

	for _, d := range st.DaemonsOf("", "h1") {
		if a := st.DaemonAddr(d); a != "10.5.0.3" {
			t.Fatalf("%s.%s renders on %s before its step", d.Type, d.ID, a)
		}
	}

	if inv := s.inventory(t); !strings.Contains(inv, `"addr":"10.5.0.9"`) || !strings.Contains(inv, `"move":{"op":"`+op) {
		t.Fatalf("inventory %s", inv)
	}

	// the mgr: failed over first, then moved once a standby
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	s.module.active, s.module.standbys = "h0", []string{"h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if m := s.move(t); m.Step != moveMgr || !slices.Contains(m.Moved, "mgr.h1") || m.Before != "100" {
		t.Fatalf("record %+v", m)
	}

	// back as a standby with another gid
	s.module.mu.Lock()
	s.module.gids = map[string]int64{"h1": 101}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	must(t, s.leader.Tick(ctx, 42, 5))

	// the OSDs under noout, done once the OSD map shows the new address
	if m := s.move(t); m.Step != moveOSD || !slices.Contains(m.Moved, "osd.3") {
		t.Fatalf("record %+v", m)
	}

	s.module.mu.Lock()
	s.module.osds = []OSD{{ID: 3, UUID: "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f", Up: true, PublicAddr: "10.5.0.9", ClusterAddr: "10.5.0.9"}}
	s.module.mu.Unlock()

	for range 8 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	want := []string{
		"addr moved " + op,
		"mgr fail " + op + " 42", "move addr " + op + " mgr.h1",
		"noout set " + op, "move addr " + op + " osd.3", "noout unset " + op,
		"mon rm " + op + " mon.h1",
		"agent cert " + op, "agent cert done " + op,
		"mgr cert done " + op,
		"addr set " + op,
	}

	if got := s.calls(); !slices.Equal(got, want) {
		t.Fatalf("module calls\n%v\nwant\n%v", got, want)
	}

	st, _, err = s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	h, _ := st.Host("h1")
	if h.Move != nil || h.Addr != "10.5.0.9" || h.AgentCert == before.AgentCert || !strings.HasPrefix(h.AgentKeys, op+"/") || !strings.HasPrefix(h.MgrKeys, op+"/") {
		t.Fatalf("after the move: %+v", h)
	}

	mon, _ := st.Find("mon.h1")
	if mon.DeployID == "0123456789abcdef" || mon.Joining {
		t.Fatalf("the mon was not deployed again: %+v", mon)
	}

	for _, d := range st.DaemonsOf("", "h1") {
		if a := st.DaemonAddr(d); a != "10.5.0.9" {
			t.Fatalf("%s.%s renders on %s after the move", d.Type, d.ID, a)
		}
	}

	if !strings.Contains(render.CephConf(st), "[v2:10.5.0.9:3300,v1:10.5.0.9:6789]") {
		t.Fatal("ceph.conf does not name the mon at its new address")
	}
}

func TestAMoveWithoutTheAddressOnTheNodePausesAndResumes(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	nodeAddr(t, s, "10.5.0.3/24")

	// another mon keeps the quorum while h1's moves; h0 in maintenance, so
	// ceph.conf goes to h1 alone
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})

		h0, _ := st.Host("h0")
		h0.Maintenance = true
		st.AddHost(h0)

		return nil
	}))

	s.module.mu.Lock()
	s.module.quorum = []string{"h0", "h1"}
	s.module.mu.Unlock()

	mv := s.acceptMove("10.5.0.9", 1)
	op := mv.Op.ID

	must(t, s.leader.Tick(ctx, 42, 5))

	// the node does not have it: paused, nothing moved, the address kept
	m := s.move(t)
	if m == nil || !m.Paused || m.Step != moveConfirm || !strings.Contains(m.Error, "does not have the address 10.5.0.9") {
		t.Fatalf("record %+v", m)
	}

	if h := s.host(t, "h1"); h.Addr != "10.5.0.3" || slices.Contains(s.calls(), "addr moved "+op) {
		t.Fatalf("moved without the address: %s %v", h.Addr, s.calls())
	}

	if inv := s.inventory(t); !strings.Contains(inv, `"paused":true`) {
		t.Fatalf("inventory %s", inv)
	}

	// paused: nothing more happens
	must(t, s.leader.Tick(ctx, 42, 5))

	if m := s.move(t); !m.Paused || m.Attempt != 1 {
		t.Fatalf("record %+v", m)
	}

	// the address added, set-addr again resumes it under a new attempt
	nodeAddr(t, s, "10.5.0.9/24")

	resume := s.accept(KindMoveResume, "", "h1", 2)

	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1].Op.Move = op
	s.module.mu.Unlock()

	s.leader.serves = func(string, int, string) bool { return true }

	for range 6 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if r := s.op(t, resume.Op.ID); r.State != wire.OpCompleted {
		t.Fatalf("resume %+v", r)
	}

	if r := s.op(t, op+".m2"); r.State != wire.OpCompleted {
		t.Fatalf("the confirm step's second attempt %+v", r)
	}

	h := s.host(t, "h1")
	if h.Move != nil || h.Addr != "10.5.0.9" {
		t.Fatalf("after the resumed move: %+v", h)
	}

	// a mon host's steps: the mon left and joined again before ceph.conf
	if got := s.calls(); !slices.Contains(got, "mon rm "+op+" mon.h1") || got[len(got)-1] != "addr set "+op {
		t.Fatalf("calls %v", got)
	}
}

func TestAMoveOfAPlainHost(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	nodeAddr(t, s, "10.5.0.9/24")
	s.leader.serves = func(string, int, string) bool { return true }

	// no daemon on h1; h0 in maintenance, so ceph.conf goes to h1 alone
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.Daemons = slices.DeleteFunc(st.Daemons, func(d state.Daemon) bool { return d.Host == "h1" })
		st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})

		h0, _ := st.Host("h0")
		h0.Maintenance = true
		st.AddHost(h0)

		return nil
	}))

	s.module.mu.Lock()
	s.module.retired = nil
	s.module.mu.Unlock()

	mv := s.acceptMove("10.5.0.9", 1)
	op := mv.Op.ID

	for range 6 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	want := []string{"addr moved " + op, "agent cert " + op, "agent cert done " + op, "addr set " + op}
	if got := s.calls(); !slices.Equal(got, want) {
		t.Fatalf("module calls\n%v\nwant\n%v", got, want)
	}

	// the steps that apply: confirm, ceph.conf, the agent's certificates
	for i, step := range []string{moveConfirm, moveConf, moveCerts} {
		if r := s.op(t, op+".m"+string(rune('1'+i))); r.State != wire.OpCompleted {
			t.Fatalf("step %s: %+v", step, r)
		}
	}

	if h := s.host(t, "h1"); h.Move != nil || h.Addr != "10.5.0.9" {
		t.Fatalf("after the move: %+v", h)
	}
}

func TestAMoveThatCannotStartEndsClosedInTheFold(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	h1, _ := s.st.Host("h1")
	h1.Maintenance = true
	s.st.AddHost(h1)
	publish(t, s.leader, s.module, s.st)

	must(t, s.leader.Tick(ctx, 42, 5))

	mv := s.acceptMove("10.5.0.9", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.op(t, mv.Op.ID); r.State != JournalFailed || !strings.Contains(r.Error, "maintenance") {
		t.Fatalf("move %+v", r)
	}

	if got := s.calls(); !slices.Equal(got, []string{"addr set " + mv.Op.ID}) || s.move(t) != nil {
		t.Fatalf("calls %v, record %+v", got, s.move(t))
	}
}

func TestAMoveRollsTheRGWWithItsKeepalivedBackLast(t *testing.T) {
	s, rgw, vip := rgwSetup(t)
	ctx := context.Background()

	addInstance(t, s.agent.fake, rgw, 1)
	nodeAddr(t, s, "10.5.0.9/24")

	mv := s.acceptMove("10.5.0.9", 1)
	op := mv.Op.ID

	// the module's certificate for the move names the new address
	cert, key := splitPEM(servingPEM(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), "10.5.0.9", "h1", "10.5.0.200"))
	out, _ := json.Marshal(map[string]string{"attempt": "0123456789abcdef", "cert": cert})
	id := "issued/" + op + "/0123456789abcdef"

	s.module.mu.Lock()
	s.module.rgwCert = string(out)
	s.module.kv[store.SecretPrefix+id+"/rgw-server.key"] = key
	s.module.retired = nil
	s.module.mu.Unlock()

	served := false
	s.leader.serves = func(addr string, _ int, chain string) bool { return served && addr == "10.5.0.9" && chain == cert }

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	// keepalived off and not rendered; the RGW at the new address with the
	// new certificate, without its keepalived
	m := s.move(t)
	if m == nil || m.Step != moveRGW || !m.VIPOff || !slices.Contains(m.Moved, "rgw.h1") || slices.Contains(m.Moved, "vip.h1") {
		t.Fatalf("record %+v", m)
	}

	step := op + ".m2"
	if off := s.op(t, step+".vip"); len(off.Docs) != 1 || owned(t, s, vip) {
		t.Fatalf("keepalived off: %+v", off)
	}

	if rev := s.op(t, step+".rev"); rev.State != wire.OpCompleted || rev.Docs["ContainerConfig/"+rgw] == "" || rev.Docs["ContainerConfig/"+vip] != "" {
		t.Fatalf("the RGW's revision: %+v", rev)
	}

	if d, _ := s.findDaemon(t, "rgw.h1"); d.Cert != id {
		t.Fatalf("rgw.h1 renders %q", d.Cert)
	}

	// serving at the new address: the keepalived's peers, then its own return
	addInstance(t, s.agent.fake, rgw, 2)
	served = true

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	keepalivedLog(s, vip, "2", "MASTER")

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if back := s.op(t, step+".back"); back.State != wire.OpCompleted || back.Docs["ContainerConfig/"+vip] == "" {
		t.Fatalf("keepalived back: %+v", back)
	}

	if m := s.move(t); m == nil || !slices.Contains(m.Done, moveRGW) || m.VIPOff || !slices.Contains(m.Moved, "vip.h1") {
		t.Fatalf("record %+v", m)
	}

	if got := s.calls(); len(got) < 3 || !slices.Equal(got[:3], []string{"addr moved " + op, "rgw cert " + op, "rgw cert done " + op + " " + id}) {
		t.Fatalf("calls %v", got)
	}
}

func (s *leaderSetup) findDaemon(t *testing.T, name string) (state.Daemon, bool) {
	t.Helper()

	st, _, err := s.leader.clusterState(context.Background(), s.leader.bridge())
	must(t, err)

	return st.Find(name)
}

// A move's roll keeps its namespace and its peers' records across its step's
// attempts: a peer whose certificate an earlier attempt set but whose
// revision failed is rolled to its end under the next attempt, not skipped
// (Codex round 1 of part B).
func TestAResumedRollFinishesAPeerItBegan(t *testing.T) {
	s, rgw, vip := rgwSetup(t)
	ctx := context.Background()
	now := time.Now()

	addInstance(t, s.agent.fake, rgw, 1)

	op := LedgerOp{Version: 1, ID: "op-00000000000000bf", Kind: KindSetAddr, Host: "h0", Addr: "10.5.0.9"}
	target := "issued/" + op.ID + "/0123456789abcdef"
	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "10.5.0.3", "h1", "10.5.0.200"))

	s.module.mu.Lock()
	s.module.kv[store.SecretPrefix+target+"/rgw-server.key"] = key
	// the first attempt's revision of the peer failed
	s.module.kv[JournalPrefix(42)+"op/"+op.ID+".roll.h1.t1.rev"] = `{"version":1,"kind":"revision","host":"h1","state":"failed"}`
	s.module.mu.Unlock()

	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: target, Cert: cert})

		return nil
	}))

	s.leader.serves = func(_ string, _ int, chain string) bool { return chain == cert }

	js, err := s.leader.bridge().Store(ctx, JournalPrefix(42))
	must(t, err)

	roll := func(try string) (bool, error) {
		done, err := s.leader.rollRGWTry(ctx, s.leader.bridge(), js, 42, 5, op, target, "roll", try)
		if errors.Is(err, errRetry) {
			return false, nil
		}

		return done, err
	}

	// the first attempt: keepalived off, the certificate set, the revision failed
	var last error
	for range 3 {
		if _, last = roll(".t1"); last != nil {
			break
		}
	}

	if last == nil || !strings.Contains(last.Error(), "did not apply") {
		t.Fatalf("the first attempt: %v", last)
	}

	if d, _ := s.findDaemon(t, "rgw.h1"); d.Cert != target || owned(t, s, vip) {
		t.Fatalf("after the first attempt: %q, keepalived owned %v", d.Cert, owned(t, s, vip))
	}

	// the next attempt finishes the peer: its revision, its keepalived back
	addInstance(t, s.agent.fake, rgw, 2)

	for range 3 {
		if _, err := roll(".t2"); err != nil {
			t.Fatal(err)
		}
	}

	keepalivedLog(s, vip, "2", "MASTER")

	done, err := roll(".t2")
	if err != nil || !done || !owned(t, s, vip) {
		t.Fatalf("the second attempt: %v %v", done, err)
	}

	if r := s.op(t, op.ID+".roll.h1.t2.rev"); r.State != wire.OpCompleted {
		t.Fatalf("the peer's revision under the second attempt: %+v", r)
	}
}

// A move's RGW step holds queued operations until it ends (Codex round 1).
func TestAMovesRGWStepHoldsQueuedOperations(t *testing.T) {
	s, rgw, vip := rgwSetup(t)
	ctx := context.Background()

	addInstance(t, s.agent.fake, rgw, 1)
	nodeAddr(t, s, "10.5.0.9/24")

	mv := s.acceptMove("10.5.0.9", 1)
	cert, key := splitPEM(servingPEM(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), "10.5.0.9", "h1", "10.5.0.200"))
	out, _ := json.Marshal(map[string]string{"attempt": "0123456789abcdef", "cert": cert})

	s.module.mu.Lock()
	s.module.rgwCert = string(out)
	s.module.kv[store.SecretPrefix+"issued/"+mv.Op.ID+"/0123456789abcdef/rgw-server.key"] = key
	s.module.mu.Unlock()

	served := false
	s.leader.serves = func(addr string, _ int, chain string) bool { return served && chain == cert }

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if m := s.move(t); m == nil || m.Step != moveRGW {
		t.Fatalf("record %+v", m)
	}

	queued := s.accept(KindRestart, "mon.h1", "h1", 2)

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if s.ended(queued.Op.ID) {
		t.Fatal("a queued operation ran during the move's RGW step")
	}

	addInstance(t, s.agent.fake, rgw, 2)
	served = true

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	keepalivedLog(s, vip, "2", "MASTER")

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if m := s.move(t); m == nil || !slices.Contains(m.Done, moveRGW) {
		t.Fatalf("record %+v", m)
	}

	if !s.ended(queued.Op.ID) {
		t.Fatal("the queued operation did not run after the RGW step")
	}
}

// A moved mgr that comes back as the active one is done when the mgr map
// shows it at the new address, else failed over again (Codex round 1).
func TestAMovedMgrBackAsTheActiveOne(t *testing.T) {
	s, _ := moveSetup(t)
	ctx := context.Background()

	mv := s.acceptMove("10.5.0.9", 2)
	op := mv.Op.ID

	must(t, s.leader.Tick(ctx, 42, 5)) // confirmed
	must(t, s.leader.Tick(ctx, 42, 5)) // the active mgr failed over

	s.module.mu.Lock()
	s.module.active, s.module.standbys = "h0", []string{"h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5)) // moved, its revision granted

	// it restarted and became the active one, still advertising the old address
	s.module.mu.Lock()
	s.module.active, s.module.standbys, s.module.activeAddr = "h1", []string{"h0"}, "10.5.0.3:6800/77"
	s.module.retired = nil
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if got := s.calls(); !slices.Equal(got, []string{"mgr fail " + op + " 42"}) || slices.Contains(s.move(t).Done, moveMgr) {
		t.Fatalf("calls %v, record %+v", got, s.move(t))
	}

	// at the new address: done
	s.module.mu.Lock()
	s.module.activeAddr = "10.5.0.9:6800/78"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if m := s.move(t); !slices.Contains(m.Done, moveMgr) {
		t.Fatalf("record %+v", m)
	}
}

// A resumed certificates step grants anew after a failed grant, with the
// issuance and the certificates before kept (Codex round 1).
func TestAResumedCertsStepGrantsAnew(t *testing.T) {
	s, before := agentSetup(t)
	ctx := context.Background()

	nodeAddr(t, s, "10.5.0.9/24")
	s.leader.serves = func(string, int, string) bool { return true }

	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.Daemons = slices.DeleteFunc(st.Daemons, func(d state.Daemon) bool { return d.Host == "h1" })
		st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})

		h0, _ := st.Host("h0")
		h0.Maintenance = true
		st.AddHost(h0)

		return nil
	}))

	mv := s.acceptMove("10.5.0.9", 1)
	op := mv.Op.ID

	// the certificates step is the third: its first self-update fails
	s.module.mu.Lock()
	s.module.kv[JournalPrefix(42)+"op/"+op+".m3.magent.self"] = `{"version":1,"kind":"self_update","host":"h1","state":"failed"}`
	s.module.mu.Unlock()

	for range 4 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	m := s.move(t)
	if m == nil || !m.Paused || m.Step != moveCerts {
		t.Fatalf("record %+v", m)
	}

	// the certificates before are back in the state until the step runs again
	if h := s.host(t, "h1"); h.AgentCert != before.AgentCert {
		t.Fatal("the failed renewal kept its certificates")
	}

	resume := s.accept(KindMoveResume, "", "h1", 2)

	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1].Op.Move = op
	s.module.mu.Unlock()

	for range 4 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if r := s.op(t, resume.Op.ID); r.State != wire.OpCompleted {
		t.Fatalf("resume %+v", r)
	}

	if r := s.op(t, op+".m4.magent.self"); r.State != wire.OpCompleted {
		t.Fatalf("the second self-update %+v", r)
	}

	h := s.host(t, "h1")
	if h.Move != nil || h.AgentCert == before.AgentCert || !strings.HasPrefix(h.AgentKeys, op+"/") {
		t.Fatalf("after the resumed move: %+v", h.Move)
	}

	// one issuance: the same certificates asked again
	if n := strings.Count(strings.Join(s.calls(), "\n"), "agent cert "+op+"\n"); n != 1 {
		t.Fatalf("issued %d times: %v", n, s.calls())
	}
}

// A drain and a move exclude each other cluster-wide (Codex round 2 of part
// B): neither starts while the other is recorded, and as a guard neither's
// steps run while the other is recorded.
func TestADrainAndAMoveExcludeEachOther(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	record := func(change func(st *state.State)) {
		must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error { change(st); return nil }))
	}

	moveOp, drainOp := "op-00000000000000c1", "op-00000000000000c2"

	// a move recorded on h0: a drain of h1 is refused and closed in the fold
	record(func(st *state.State) {
		h, _ := st.Host("h0")
		h.Move = &state.Move{Op: moveOp, From: "10.5.0.2", To: "10.5.0.8", Paused: true}
		st.AddHost(h)
	})

	drain := s.accept(KindDrain, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.op(t, drain.Op.ID); r.State != JournalFailed || !strings.Contains(r.Error, "changing") || !slices.Contains(s.calls(), "drain done "+drain.Op.ID) {
		t.Fatalf("drain %+v, calls %v", r, s.calls())
	}

	// a drain recorded on h1 instead: a move of h0 is refused and closed
	record(func(st *state.State) {
		h, _ := st.Host("h0")
		h.Move = nil
		st.AddHost(h)

		h1, _ := st.Host("h1")
		h1.Drain = &state.Drain{Op: drainOp, Paused: true}
		st.AddHost(h1)
	})

	s.accept(KindSetAddr, "", "h0", 2)

	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1].Op.Addr = "10.5.0.8"
	mv := s.module.ledger[len(s.module.ledger)-1]
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.op(t, mv.Op.ID); r.State != JournalFailed || !strings.Contains(r.Error, "draining") || !slices.Contains(s.calls(), "addr set "+mv.Op.ID) {
		t.Fatalf("move %+v, calls %v", r, s.calls())
	}

	// both recorded (a guard): neither's step runs
	record(func(st *state.State) {
		h, _ := st.Host("h0")
		h.Move = &state.Move{Op: moveOp, From: "10.5.0.2", To: "10.5.0.8"}
		st.AddHost(h)

		h1, _ := st.Host("h1")
		h1.Drain = &state.Drain{Op: drainOp}
		st.AddHost(h1)
	})

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	h0, _ := st.Host("h0")
	h1, _ := st.Host("h1")

	if h0.Move.Step != "" || h1.Drain.Step != "" || s.ended(moveOp+".m1") || s.ended(drainOp+".d1") {
		t.Fatalf("a step ran: move %+v, drain %+v", h0.Move, h1.Drain)
	}
}
