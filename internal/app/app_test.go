// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"github.com/trozet/ovn-light/internal/offload"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/policy"
)

func TestProposalPersistenceAndDemoImmutability(t *testing.T) {
	dir := t.TempDir()
	a, e := New("demo", dir, nil, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	s := Demo()
	a.Load(s)
	if a.Writes {
		t.Fatal("demo must never permit writes")
	}
	v := a.State()
	var intent policy.Intent
	for _, f := range v.Findings {
		if f.CanRecommend {
			intent = policy.Intent{Kind: "NetworkPolicy", Source: f.Source, Destination: f.Destination, Protocol: f.Protocol, Port: f.Destination.Port}
		}
	}
	p, e := a.Prepare(context.Background(), intent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Apply(context.Background(), p.ID); e == nil {
		t.Fatal("demo wrote to cluster")
	}
	b, e := New("demo", dir, nil, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	if len(b.Plans()) != 1 || b.Plans()[0].ID != p.ID {
		t.Fatal("audit record did not survive restart")
	}
	returned := b.Plans()
	returned[0].Objects[0].SetName("tampered")
	if b.Plans()[0].Objects[0].GetName() == "tampered" {
		t.Fatal("API response mutated server proposal")
	}
}

func TestDropProposalRetainsObservedNetwork(t *testing.T) {
	a, _ := New("demo", "", nil, nil, false)
	a.Load(Demo())
	for _, f := range a.State().Findings {
		if !f.CanRecommend {
			continue
		}
		i := policy.Intent{Kind: "Policy", FindingID: f.ID, Source: f.Source, Destination: f.Destination, Protocol: f.Protocol, Port: f.Destination.Port}
		p, e := a.Prepare(context.Background(), i)
		if e != nil || p.Scope.Network != "default" {
			t.Fatal(p, e)
		}
		i.Source.Network = "analytics/data"
		if _, e = a.Prepare(context.Background(), i); e == nil {
			t.Fatal("drop proposal was moved to another network")
		}
		i.FindingID = "expired"
		if _, e = a.Prepare(context.Background(), i); e == nil {
			t.Fatal("missing observation was silently ignored")
		}
		return
	}
	t.Fatal("missing demo finding")
}

func TestOffloadStaleLiveEvidence(t *testing.T) {
	a, _ := New("live", "", nil, nil, false)
	s := Demo()
	s.CapturedAt = time.Now().Add(-5 * time.Minute)
	for i := range s.Nodes {
		s.Nodes[i].CapturedAt = s.CapturedAt
		s.Nodes[i].Offload.CapturedAt = s.CapturedAt
	}
	a.Load(s)
	r := a.Offload(offload.Options{})
	if len(r.Nodes) == 0 || r.Nodes[0].State != "unknown" || r.Issues != 0 {
		t.Fatal(r)
	}
	for _, p := range r.Paths {
		if p.Status != "unknown" || p.Issue {
			t.Fatal(p)
		}
	}
}

func TestDPUCollectionErrorsAreShown(t *testing.T) {
	a, _ := New("live", "", nil, nil, false)
	s := Demo()
	s.Inventory.DiagnosticErrors = map[string]string{"dpuCollection": "dpu0: no such key"}
	a.Load(s)
	if !slices.Contains(a.State().Errors, "dpu0: no such key") {
		t.Fatal(a.State().Errors)
	}
}

func TestIncompleteOffloadPathRetainsWorkloadNetwork(t *testing.T) {
	s := Demo()
	s.Nodes[0].Flows = "ufid:incomplete,recirc_id(0),in_port(4),ipv4(src=10.244.0.8,dst=10.244.0.12,proto=6),tcp(src=41912,dst=8080),packets:30,bytes:3000,offloaded:partial,dp:ovs,actions:recirc(999)"
	a, _ := New("snapshot", "", nil, nil, false)
	a.Load(s)
	r := a.Offload(offload.Options{Network: "default"})
	if len(r.Paths) != 1 || r.Paths[0].Source.Pod != "web-7b49" || r.Paths[0].Complete {
		t.Fatal(r)
	}
	detail := a.Offload(offload.Options{ID: r.Paths[0].ID})
	if len(detail.Nodes) != 1 || detail.Nodes[0].Name != "kind-worker" {
		t.Fatal("unrelated node evidence returned", detail.Nodes)
	}
}

func TestAllPortsProbeRequiresSpecificPort(t *testing.T) {
	for _, tc := range []struct {
		all   bool
		port  int
		valid bool
	}{
		{true, 0, false}, {true, -1, false}, {true, 65536, false}, {true, 8080, true}, {false, 0, true}, {false, 8080, true}, {false, 8081, false},
	} {
		i := policy.Intent{Protocol: "TCP", AllPorts: tc.all, Port: 8080}
		if tc.all {
			i.Port = 0
		}
		got, err := probeIntent(i, tc.port)
		if (err == nil) != tc.valid {
			t.Fatal(tc, got, err)
		}
		if tc.valid && (got.AllPorts || got.Port != 8080) {
			t.Fatal("probe scope not explicit", got)
		}
	}
}

func TestUnconfirmedSenderWarningSurvivesReview(t *testing.T) {
	a, _ := New("demo", "", nil, nil, false)
	a.Load(Demo())
	var intent policy.Intent
	for j := range a.view.Findings {
		f := &a.view.Findings[j]
		if f.CanRecommend {
			intent = policy.Intent{Kind: "Policy", FindingID: f.ID, Source: f.Source, Destination: f.Destination, Protocol: "TCP", AllPorts: true}
			f.Source = model.Endpoint{Network: f.Source.Network, Node: f.Source.Node}
			f.CanRecommend = false
			break
		}
	}
	if intent.FindingID == "" {
		t.Fatal("missing finding")
	}
	p, err := a.Prepare(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "does not confirm") {
		t.Fatal(p.Warnings)
	}
}
