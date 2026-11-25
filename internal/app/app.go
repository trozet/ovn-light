// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/trozet/ovn-light/internal/flowtest"
	"github.com/trozet/ovn-light/internal/history"
	"github.com/trozet/ovn-light/internal/kube"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/offload"
	"github.com/trozet/ovn-light/internal/ovn"
	"github.com/trozet/ovn-light/internal/policy"
	"github.com/trozet/ovn-light/internal/qos"
	"github.com/trozet/ovn-light/internal/routing"
	"github.com/trozet/ovn-light/internal/topology"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type App struct {
	TrafficTest   *flowtest.Manager
	History       *history.Store
	qos           qos.Report
	routing       routing.Report
	OffloadGrace  time.Duration
	offload       offload.Store
	mu            sync.RWMutex
	analysis      sync.Mutex
	operation     sync.Mutex
	diagnostic    sync.Mutex
	snapshot      model.Snapshot
	view          model.View
	plans         map[string]*policy.Plan
	Collector     *kube.Collector
	Client        *kube.Client
	Mode          string
	Writes        bool
	DataDir       string
	collecting    bool
	topology      topology.Store
	topologyMu    sync.Mutex
	topologyCache map[string]topology.Graph
}
type diskPlan struct {
	Plan        policy.Plan `json:"plan"`
	Fingerprint string      `json:"fingerprint"`
}

func New(mode, dataDir string, client *kube.Client, collector *kube.Collector, writes bool) (*App, error) {
	a := &App{Mode: mode, DataDir: dataDir, Client: client, Collector: collector, Writes: writes && mode == "live", plans: map[string]*policy.Plan{}}
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			return nil, err
		}
		files, err := filepath.Glob(filepath.Join(dataDir, "plan-*.json"))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			var saved diskPlan
			if err = json.Unmarshal(b, &saved); err != nil {
				return nil, fmt.Errorf("read audit record %s: %w", file, err)
			}
			p := saved.Plan
			p.Fingerprint = saved.Fingerprint
			if p.Status == "applying" || p.Status == "rolling-back" {
				p.Status = "interrupted"
				p.Warnings = append(p.Warnings, "The process stopped during a write. Inspect planned object names in the cluster before retrying; the recorded objects can be rolled back.")
			}
			a.plans[p.ID] = &p
		}
	}
	return a, nil
}
func (a *App) Load(s model.Snapshot) {
	a.analysis.Lock()
	defer a.analysis.Unlock()
	a.mu.RLock()
	var previous *model.Snapshot
	if a.snapshot.Version != 0 {
		old := a.snapshot
		previous = &old
	}
	a.mu.RUnlock()
	v := ovn.Analyze(s, previous)
	for _, key := range []string{"collectionScope", "dpuCollection"} {
		if message := s.Inventory.DiagnosticErrors[key]; message != "" {
			v.Errors = append(v.Errors, message)
		}
	}
	report := routing.Analyze(s, v, &a.routing)
	qosReport := qos.Analyze(s)
	if a.History != nil {
		a.History.Record(v, s.Inventory)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.offload.Grace = a.OffloadGrace
	v.OffloadIssues = a.offload.Update(v.Offload)
	a.TrafficTest.Observe(v, a.offload.Latest(), s.Inventory)
	v.TestPaths, v.TestPathsLimited = nil, nil
	v.OffloadIssueCount = len(v.OffloadIssues)
	if len(v.OffloadIssues) > 100 {
		v.OffloadIssues = v.OffloadIssues[:100]
	}
	v.Offload = model.OffloadReport{}
	a.snapshot = s
	a.routing = report
	a.qos = qosReport
	a.topology.Inventory(s.Inventory)
	a.topology.Update(v)
	v.Traffic = nil
	a.view = v
	a.view.Mode = a.Mode
	a.view.WritesEnabled = a.Writes
}
func (a *App) Topology(o topology.Options) topology.Graph {
	a.topologyMu.Lock()
	defer a.topologyMu.Unlock()
	a.mu.RLock()
	now := time.Now().UTC()
	if a.Mode != "live" {
		now = a.snapshot.CapturedAt
	}
	revision := a.snapshot.CapturedAt.UnixNano()
	s := a.topology.Snapshot()
	a.mu.RUnlock()
	key := fmt.Sprintf("%d/%d/%+v", revision, now.Unix()/15, o)
	if cached, ok := a.topologyCache[key]; ok {
		return cached
	}
	g := s.Graph(o, now)
	if len(a.topologyCache) >= 32 || a.topologyCache == nil {
		a.topologyCache = map[string]topology.Graph{}
	}
	a.topologyCache[key] = g
	return g
}
func (a *App) Routing(o routing.Options) routing.Report {
	a.mu.RLock()
	report := a.routing
	stale := a.Mode == "live" && time.Since(a.snapshot.CapturedAt) > 2*time.Minute
	a.mu.RUnlock()
	o.Stale = stale
	return routing.Filter(report, o)
}
func (a *App) Offload(o offload.Options) model.OffloadReport {
	a.mu.RLock()
	defer a.mu.RUnlock()
	o.Stale = a.Mode == "live" && time.Since(a.snapshot.CapturedAt) > 2*time.Minute
	return a.offload.Report(o)
}
func (a *App) State() model.View {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v := a.view
	v.Mode = a.Mode
	v.WritesEnabled = a.Writes
	v.Collecting = a.collecting
	if a.Mode == "live" && time.Since(v.CollectedAt) > 2*time.Minute {
		v.OffloadIssues = nil
		v.OffloadIssueCount = 0
	}
	return v
}
func (a *App) Snapshot() model.Snapshot { a.mu.RLock(); defer a.mu.RUnlock(); return a.snapshot }
func (a *App) Refresh(ctx context.Context) error {
	if a.Collector == nil {
		return nil
	}
	a.mu.Lock()
	if a.collecting {
		a.mu.Unlock()
		return fmt.Errorf("collection is already running")
	}
	a.collecting = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.collecting = false; a.mu.Unlock() }()
	s, err := a.Collector.Capture(ctx)
	if err != nil {
		a.mu.Lock()
		a.view.Errors = append([]string{err.Error()}, a.snapshot.Inventory.Errors...)
		a.mu.Unlock()
		return err
	}
	a.Load(s)
	return nil
}
func (a *App) Run(ctx context.Context, interval time.Duration) {
	for {
		_ = a.Refresh(ctx)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (a *App) persist(p *policy.Plan) error {
	if a.DataDir == "" {
		if a.Writes {
			return fmt.Errorf("writes require a writable audit directory")
		}
		return nil
	}
	b, err := json.MarshalIndent(diskPlan{Plan: *p, Fingerprint: p.Fingerprint}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(a.DataDir, ".plan-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(a.DataDir, "plan-"+p.ID+".json"))
}
func clonePlan(p *policy.Plan) policy.Plan {
	b, _ := json.Marshal(p)
	var out policy.Plan
	_ = json.Unmarshal(b, &out)
	return out
}
func (a *App) Plans() []policy.Plan {
	a.operation.Lock()
	defer a.operation.Unlock()
	out := []policy.Plan{}
	for _, p := range a.plans {
		out = append(out, clonePlan(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (a *App) Prepare(ctx context.Context, i policy.Intent) (policy.Plan, error) {
	a.operation.Lock()
	defer a.operation.Unlock()
	var evidence *model.Finding
	if i.FindingID != "" {
		var finding *model.Finding
		for _, f := range a.State().Findings {
			if f.ID == i.FindingID {
				finding = &f
				break
			}
		}
		if finding == nil {
			return policy.Plan{}, fmt.Errorf("drop evidence expired; refresh the issue or start a new connection review")
		}
		evidence = finding
		network := ""
		for _, e := range []model.Endpoint{finding.Source, finding.Destination} {
			if e.Network != "" {
				if network != "" && network != e.Network {
					return policy.Plan{}, fmt.Errorf("this drop crosses networks; review connectivity separately")
				}
				network = e.Network
			}
		}
		if network != "" {
			for _, e := range []*model.Endpoint{&i.Source, &i.Destination} {
				if e.Network != "" && e.Network != network {
					return policy.Plan{}, fmt.Errorf("proposal must stay on the drop's observed network %s", network)
				}
				e.Network = network
			}
		}
	}
	inv := a.Snapshot().Inventory
	if a.Mode == "live" {
		var err error
		inv, err = a.Client.Inventory(ctx)
		if err != nil {
			return policy.Plan{}, err
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return policy.Plan{}, err
	}
	id := hex.EncodeToString(idBytes)
	p, err := policy.Build(inv, i, id)
	if err != nil {
		return p, err
	}
	if evidence != nil && evidence.Source.UID == "" {
		p.Warnings = append(p.Warnings, "The source workload was selected by the operator. The drop evidence does not confirm that workload as the sender.")
	}
	if p.FirewallChange != nil && evidence != nil {
		matched := false
		for _, cause := range evidence.Causes {
			if cause.Type == "EgressFirewall" && cause.Namespace == p.Intent.Source.Namespace && cause.Rule == strconv.Itoa(p.FirewallChange.Index) {
				matched = true
			}
		}
		if !matched || evidence.Source.UID != "" && evidence.Source.UID != p.Intent.Source.UID || evidence.Destination.IP != "" && evidence.Destination.IP != p.Intent.Destination.IP || evidence.Protocol != "" && evidence.Protocol != p.Intent.Protocol || evidence.Destination.Port > 0 && evidence.Destination.Port != p.Intent.Port {
			return p, fmt.Errorf("the selected connection or matching firewall rule differs from the drop evidence; refresh or start a new external connection review")
		}
	}
	if a.Mode == "live" && a.Writes {
		for _, o := range p.Objects {
			if _, err = a.writeObject(ctx, &p, o, true); err != nil {
				return p, fmt.Errorf("admission dry-run failed: %w", err)
			}
		}
	} else {
		p.Warnings = append(p.Warnings, "Export only: this server cannot apply changes; cluster admission has not validated this proposal.")
	}
	if err = a.persist(&p); err != nil {
		return p, err
	}
	a.plans[id] = &p
	return clonePlan(&p), nil
}
func (a *App) Apply(ctx context.Context, id string) (policy.Plan, error) {
	a.operation.Lock()
	defer a.operation.Unlock()
	p, ok := a.plans[id]
	if !ok {
		return policy.Plan{}, fmt.Errorf("proposal not found")
	}
	fail := func(e error) (policy.Plan, error) { return clonePlan(p), e }
	if !a.Writes {
		return fail(fmt.Errorf("cluster writes are disabled"))
	}
	if p.Status != "review" {
		return fail(fmt.Errorf("proposal is %s; create a fresh proposal to make another change", p.Status))
	}
	if time.Now().After(p.ExpiresAt) {
		return fail(fmt.Errorf("proposal expired; generate and review a new one"))
	}
	inv, err := a.Client.Inventory(ctx)
	if err != nil {
		return fail(err)
	}
	if len(inv.Errors) > 0 || policy.Fingerprint(inv) != p.Fingerprint {
		return fail(fmt.Errorf("policies, networks or workload identity changed; generate and review a new proposal"))
	}
	for _, o := range p.Objects {
		if _, err = a.writeObject(ctx, p, o, true); err != nil {
			return fail(fmt.Errorf("admission dry-run failed: %w", err))
		}
	}
	p.Status = "applying"
	if err = a.persist(p); err != nil {
		p.Status = "review"
		return fail(err)
	}
	for _, o := range p.Objects {
		created, e := a.writeObject(ctx, p, o, false)
		if e != nil {
			p.Status = "apply-failed"
			p.Warnings = append(p.Warnings, "Write failed; some changes may have been applied. On a transport timeout inspect the planned objects before retrying. "+e.Error())
			persistErr := a.persist(p)
			return fail(errors.Join(e, persistErr))
		}
		p.Applied = append(p.Applied, policy.ObjectRef{Kind: created.GetKind(), Namespace: created.GetNamespace(), Name: created.GetName(), UID: string(created.GetUID()), SpecHash: kube.SpecHash(created)})
		if err = a.persist(p); err != nil {
			return fail(fmt.Errorf("object was created but its audit record could not be saved: %w", err))
		}
	}
	p.Status = "applied"
	p.Verification = "Applied; connectivity has not been verified."
	if p.QoSChange != nil {
		p.Verification = "Applied; refresh QoS to inspect OVN convergence. Packet treatment has not been verified."
	}
	err = a.persist(p)
	return clonePlan(p), err
}
func (a *App) Rollback(ctx context.Context, id string) (policy.Plan, error) {
	a.operation.Lock()
	defer a.operation.Unlock()
	p, ok := a.plans[id]
	if !ok {
		return policy.Plan{}, fmt.Errorf("proposal not found")
	}
	if !a.Writes {
		return clonePlan(p), fmt.Errorf("cluster writes are disabled")
	}
	if len(p.Applied) == 0 {
		return clonePlan(p), fmt.Errorf("no recorded objects to roll back")
	}
	p.Status = "rolling-back"
	if err := a.persist(p); err != nil {
		return clonePlan(p), err
	}
	for len(p.Applied) > 0 {
		index := len(p.Applied) - 1
		ref := p.Applied[index]
		var err error
		if p.QoSChange != nil {
			err = a.Client.RollbackQoS(ctx, p.QoSChange, ref)
		} else if p.FirewallChange != nil {
			err = a.Client.RollbackFirewall(ctx, p.FirewallChange, ref)
		} else {
			err = a.Client.Rollback(ctx, ref, p.ID)
		}
		if err != nil && (p.FirewallChange != nil || p.QoSChange != nil || !apierrors.IsNotFound(err)) {
			p.Status = "rollback-failed"
			_ = a.persist(p)
			return clonePlan(p), err
		}
		p.Applied = p.Applied[:index]
		if err = a.persist(p); err != nil {
			return clonePlan(p), err
		}
	}
	p.Status = "rolled-back"
	p.Verification = "Created resources were removed. Previous policy behavior should return after OVN converges."
	if p.QoSChange != nil {
		p.Verification = "Previous QoS spec restored. Refresh QoS to inspect convergence."
	}
	if p.FirewallChange != nil {
		p.Verification = "The inserted allow rule was removed; the existing EgressFirewall was preserved. Verify denial after OVN converges."
	}
	err := a.persist(p)
	return clonePlan(p), err
}

func (a *App) writeObject(ctx context.Context, p *policy.Plan, o unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	if p.QoSChange != nil {
		return a.Client.PatchQoS(ctx, p.QoSChange, o, dryRun)
	}
	if p.FirewallChange != nil {
		return a.Client.PatchFirewall(ctx, p.FirewallChange, o, dryRun)
	}
	return a.Client.Create(ctx, o, dryRun)
}
func (a *App) Verify(ctx context.Context, id string, port int) (policy.Plan, error) {
	a.operation.Lock()
	defer a.operation.Unlock()
	p, ok := a.plans[id]
	if !ok {
		return policy.Plan{}, fmt.Errorf("proposal not found")
	}
	if !a.Writes || a.Client == nil {
		return clonePlan(p), fmt.Errorf("active probes require a live server with writes enabled")
	}
	if p.Status != "applied" && p.Status != "verified" {
		return clonePlan(p), fmt.Errorf("apply the proposal before verifying it")
	}
	intent, err := probeIntent(p.Intent, port)
	if err != nil {
		return clonePlan(p), err
	}
	message, err := a.Client.Probe(ctx, intent)
	p.VerificationPort = intent.Port
	p.VerificationSucceeded = err == nil
	if err != nil {
		p.Status = "applied"
		p.Verification = "Not verified: " + err.Error()
	} else {
		p.Status = "verified"
		p.Verification = message
		if p.Intent.AllPorts {
			p.Status = "applied"
			p.Verification += " Only this TCP port was tested; other ports were not verified."
		}
	}
	saveErr := a.persist(p)
	return clonePlan(p), errors.Join(err, saveErr)
}

func probeIntent(i policy.Intent, port int) (policy.Intent, error) {
	if port < 0 || port > 65535 {
		return i, fmt.Errorf("choose a TCP test port between 1 and 65535")
	}
	if i.AllPorts {
		if port == 0 {
			return i, fmt.Errorf("choose a specific listening TCP port to test this all-ports allowance")
		}
		i.Port = port
		i.AllPorts = false
	} else if port != 0 && port != i.Port {
		return i, fmt.Errorf("test port must match the proposed destination port")
	}
	return i, nil
}
