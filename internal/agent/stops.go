package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/api/common"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// Best-effort noout on a Talos reboot or shutdown outside the orchestrator
// (plan 04, step 5): the agent follows its node's stop sequences (reboot,
// shutdown, upgrade, reset) by its MachineStatus stage and by Talos's
// sequence events, and reports each one to the active module
// (POST /v1/going-down, its agent client certificate), which holds the host's
// noout until the host is back. It only notifies: the reboot is Talos's.

// stopSequences are Talos's sequences that stop the node's containers.
var stopSequences = map[string]bool{"reboot": true, "shutdown": true, "upgrade": true, "reset": true}

// stopStage reports whether a machine stage is a stop sequence's; Talos sets
// it at the start of the sequence, before it stops containers.
func stopStage(s runtime.MachineStage) bool {
	switch s {
	case runtime.MachineStageRebooting, runtime.MachineStageShuttingDown, runtime.MachineStageUpgrading, runtime.MachineStageResetting:
		return true
	}

	return false
}

const (
	// cancelQuiet is how long after the last stop sequence started none may
	// start again before a stop whose sequences were all cancelled counts as
	// cancelled: a reboot may replace a reboot, its START right after its
	// predecessor's cancellation
	cancelQuiet = 60 * time.Second
	// goingDownFor bounds a report's retries; they outlive the agent's own
	// stop until its container is killed
	goingDownFor = 2 * time.Minute
)

var (
	goingDownEvery = time.Second
	// watchRetry is the pause before a broken watch is set up again
	watchRetry = 2 * time.Second
)

// stopTracker follows its node's stop sequences on one boot.
type stopTracker struct {
	stage runtime.MachineStage
	seen  bool // a stage was seen
	// starts and canceled count each stop sequence's START events and the
	// outcomes Talos reports as cancelled (a NOOP with CANCELED: another
	// sequence took over); open the STARTs seen without an outcome yet, which
	// an outcome must match (the watch starts from now: an earlier
	// sequence's outcome is ignored)
	starts, canceled, open map[string]int
	// other: a stop sequence ended otherwise (any other error makes Talos
	// shut its services down and reboot; a successful reboot reports one)
	other     bool
	lastStart time.Time
	signalled bool
}

// stageChanged takes a new stage; true when it starts a stop. The first
// stage seen is the baseline: an agent starting on a boot whose stage stayed
// in a stop stage after a cancelled sequence reports nothing (a stop that is
// starting has its sequence's START, before containers stop).
func (t *stopTracker) stageChanged(s runtime.MachineStage) bool {
	if !t.seen {
		t.stage, t.seen = s, true

		return false
	}

	was := stopStage(t.stage)
	t.stage = s

	if stopStage(s) && !was {
		t.signalled = true

		return true
	}

	return false
}

// sequence takes a sequence event; true when a stop sequence starts (each
// START, also on the same stage: Talos keeps the stage after a cancelled
// sequence, so a later reboot changes no stage).
func (t *stopTracker) sequence(ev *machine.SequenceEvent, now time.Time) bool {
	seq := ev.GetSequence()
	if !stopSequences[seq] {
		return false
	}

	if t.starts == nil {
		t.starts, t.canceled, t.open = map[string]int{}, map[string]int{}, map[string]int{}
	}

	switch ev.GetAction() {
	case machine.SequenceEvent_START:
		t.starts[seq]++
		t.open[seq]++
		t.lastStart, t.signalled = now, true

		return true
	case machine.SequenceEvent_NOOP:
		// not started (LOCKED: no START was published for it), or an outcome
		// without a START this agent saw: no outcome of a sequence it follows
		if ev.GetError() == nil || ev.GetError().GetCode() == common.Code_LOCKED || t.open[seq] == 0 {
			return false
		}

		t.open[seq]--

		if ev.GetError().GetCode() == common.Code_CANCELED {
			t.canceled[seq]++
		} else {
			t.other = true
		}
	case machine.SequenceEvent_STOP:
		// a sequence's run returned; its outcome follows as a NOOP, if any
	}

	return false
}

// cancelled reports whether the stop is evidently cancelled: on this boot
// every stop sequence that started ended cancelled and none started for
// cancelQuiet. No timer ends a stop otherwise (a shutdown hook may take long).
func (t *stopTracker) cancelled(now time.Time) bool {
	if !t.signalled || t.other || len(t.starts) == 0 {
		return false
	}

	for seq, n := range t.starts {
		if t.canceled[seq] < n {
			return false
		}
	}

	return now.Sub(t.lastStart) >= cancelQuiet
}

// stopSource is what StopWatch reads of its node (internal/talos Client).
type stopSource interface {
	BootID(ctx context.Context, node string) (string, error)
	WatchMachineStage(ctx context.Context, node string, fn func(runtime.MachineStage)) error
	WatchSequences(ctx context.Context, node, tailID string, fn func(*machine.SequenceEvent)) (string, error)
}

// StopWatch follows the agent's own node's stop sequences and reports each
// one to the module.
type StopWatch struct {
	Talos stopSource
	// Notify sends one going-down report: the boot and the stop's id
	Notify func(ctx context.Context, boot, stop string) error
	Now    func() time.Time
	Log    func(format string, args ...any)

	mu   sync.Mutex
	boot string
	// stop identifies the last stop signalled: the boot id, a nonce of this
	// agent process and the signal's number, so a stop is never taken for an
	// earlier one on the same boot, also after the agent restarted
	stop, nonce string
	t           stopTracker
	due         int // reports due (one per stop signal)
	sent        int // the last one delivered
	sending     bool
	wg          sync.WaitGroup
}

func (w *StopWatch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}

	return time.Now()
}

func (w *StopWatch) logf(format string, args ...any) {
	if w.Log != nil {
		w.Log(format, args...)
	}
}

// Run reads the boot id, then watches the machine stage and the sequence
// events until ctx ends, each watch set up again when it breaks.
func (w *StopWatch) Run(ctx context.Context) {
	for {
		boot, err := w.Talos.BootID(ctx, "")
		if err == nil {
			w.mu.Lock()
			w.boot = boot
			w.mu.Unlock()

			break
		}

		w.logf("stop watch: %v", err)

		if !sleep(ctx, watchRetry) {
			return
		}
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		for {
			if err := w.Talos.WatchMachineStage(ctx, "", w.stage); err != nil {
				w.logf("stop watch: %v", err)
			}

			if !sleep(ctx, watchRetry) {
				return
			}
		}
	})

	wg.Go(func() {
		tail := ""

		for {
			var err error
			if tail, err = w.Talos.WatchSequences(ctx, "", tail, w.sequence); err != nil {
				w.logf("stop watch: %v", err)
			}

			if !sleep(ctx, watchRetry) {
				return
			}
		}
	})

	wg.Wait()
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (w *StopWatch) stage(s runtime.MachineStage) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.t.stageChanged(s) {
		w.signal()
	}
}

func (w *StopWatch) sequence(ev *machine.SequenceEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.t.sequence(ev, w.now()) {
		w.signal()
	}
}

// signal makes a report due, sent at once and retried until delivered or
// goingDownFor passed. Under mu.
func (w *StopWatch) signal() {
	w.due++

	if w.nonce == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		w.nonce = hex.EncodeToString(b)
	}

	w.stop = fmt.Sprintf("%s.%s.%d", w.boot, w.nonce, w.due)

	if w.sending || w.Notify == nil {
		return
	}

	w.sending = true

	w.wg.Go(w.send)
}

// send delivers the newest due report; its own deadline, not the agent's
// context, so it outlives the agent's stop.
func (w *StopWatch) send() {
	ctx, cancel := context.WithTimeout(context.Background(), goingDownFor)
	defer cancel()

	for {
		w.mu.Lock()
		due, boot, stop := w.due, w.boot, w.stop

		if w.sent >= due {
			w.sending = false
			w.mu.Unlock()

			return
		}

		w.mu.Unlock()

		err := w.Notify(ctx, boot, stop)
		if err == nil {
			w.mu.Lock()
			w.sent = max(w.sent, due)
			w.mu.Unlock()

			continue
		}

		w.logf("going-down report: %v", err)

		select {
		case <-ctx.Done():
			w.mu.Lock()
			w.sending = false
			w.mu.Unlock()

			return
		case <-time.After(goingDownEvery):
		}
	}
}

// Report is the node's boot id and, if its last stop was evidently
// cancelled, that stop's id (the status record's boot and stop_cancelled).
func (w *StopWatch) Report() (boot, cancelled string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.t.cancelled(w.now()) {
		cancelled = w.stop
	}

	return w.boot, cancelled
}

// Wait joins a report in flight.
func (w *StopWatch) Wait() { w.wg.Wait() }

// moduleTarget is the module that polled the agent last: the mgr its client
// certificate names and the address it gave (the status poll's header).
type moduleTarget struct {
	Mgr, Addr string
}

// moduleAddrHeader names the polling module's address (module.py
// MODULE_ADDR_HEADER).
const moduleAddrHeader = "X-Cephadm-Talos-Module"

// pollerSeen keeps the module that polls the status: the mgr of its verified
// client certificate, at the address it names.
func (a *Agent) pollerSeen(r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return
	}

	id, err := pki.CertIdentity(r.TLS.PeerCertificates[0])
	addr := net.ParseIP(r.Header.Get(moduleAddrHeader))

	if err != nil || id.Role != pki.RoleMgr || addr == nil {
		return
	}

	a.modMu.Lock()
	a.module = moduleTarget{Mgr: id.Name, Addr: addr.String()}
	a.modMu.Unlock()
}

// goingDown is the report's body (bridge.py going_down).
type goingDown struct {
	Version int    `json:"version"`
	FSID    string `json:"fsid"`
	Host    string `json:"host"`
	Boot    string `json:"boot"`
	Stop    string `json:"stop"`
}

// NotifyDown sends one going-down report to the module that polled last,
// connecting by its mgr's certificate identity: a wrong address only fails.
func (a *Agent) NotifyDown(ctx context.Context, boot, stop string) error {
	a.modMu.Lock()
	t := a.module
	a.modMu.Unlock()

	if t.Addr == "" || a.ClientTLS == nil || a.Channel == nil {
		return errors.New("no module has polled this agent yet")
	}

	body, err := json.Marshal(goingDown{Version: wire.Version, FSID: a.Channel.Self.FSID, Host: a.Channel.Self.Name, Boot: boot, Stop: stop})
	if err != nil {
		return err
	}

	cfg := a.ClientTLS.Clone()
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no server certificate")
		}

		if _, err := pki.Require(cs.PeerCertificates[0], pki.Identity{FSID: a.Channel.Self.FSID, Role: pki.RoleMgr, Name: t.Mgr}); err != nil {
			return err
		}

		return a.CRL.Check(cs.PeerCertificates[0])
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(t.Addr, dialPort())+"/v1/going-down", bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("module answered %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}

	return nil
}
