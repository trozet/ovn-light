// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"fmt"
	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCollectorCachesUnchangedEvidenceAndInvalidates(t *testing.T) {
	flow := "ufid:a,recirc_id(0),in_port(1),packets:10,bytes:100,actions:drop"
	tables, traces := 0, 0
	c := Collector{CacheTTL: time.Minute, MaxDetraces: 1}
	c.exec = func(ctx context.Context, target Target, args []string) (string, error) {
		switch {
		case args[0] == "ovn-sbctl" || args[0] == "ovn-nbctl":
			tables++
			return `{"headings":["_uuid"],"data":[]}`, nil
		case args[0] == "ovs-vsctl":
			return `{"headings":["_uuid"],"data":[]}`, nil
		case strings.Contains(strings.Join(args, " "), "dpctl/dump-flows"):
			return flow, nil
		case strings.Contains(strings.Join(args, " "), "dpctl/show"):
			return "system@ovs-system:\n port 1: pod0", nil
		default:
			traces++
			return "cookie=0x123,actions=drop", nil
		}
	}
	target := nodeTargets{ovs: Target{Pod: "ovs"}, ovn: Target{Pod: "ovn"}}
	n := c.captureNode(context.Background(), "node", target, "inventory-v1", nil)
	if tables != 6 || traces != 1 || !n.Collection.FlowComplete {
		t.Fatal(n, tables, traces)
	}
	flow = strings.Replace(flow, "packets:10", "packets:20", 1)
	n = c.captureNode(context.Background(), "node", target, "inventory-v1", nil)
	if tables != 6 || traces != 1 || !n.Collection.MetadataCached || n.Collection.DetraceHits != 1 || n.Collection.Commands != 3 {
		t.Fatal(n.Collection, tables, traces)
	}
	flow = strings.Replace(flow, "actions:drop", "actions:set(skb_mark(1)),drop", 1)
	c.captureNode(context.Background(), "node", target, "inventory-v1", nil)
	if traces != 2 {
		t.Fatal("changed translation reused", traces)
	}
	c.captureNode(context.Background(), "node", target, "inventory-v2", nil)
	if tables != 12 || traces != 3 {
		t.Fatal("inventory change did not invalidate evidence", tables, traces)
	}
	c.cache["node"] = nodeCache{At: time.Now().Add(-2 * time.Minute), Key: "inventory-v2", Traces: map[string]traceCache{}}
	c.captureNode(context.Background(), "node", target, "inventory-v2", nil)
	if tables != 18 {
		t.Fatal("expired metadata reused")
	}
}

func TestMetadataKeyIgnoresStatusButTracksScope(t *testing.T) {
	inv := model.Inventory{Pods: []core.Pod{{ObjectMeta: meta.ObjectMeta{Name: "pod", Namespace: "app", UID: "uid", ResourceVersion: "1", Labels: map[string]string{"app": "one"}}}}}
	key := inventoryKey(inv)
	inv.Pods[0].ResourceVersion = "2"
	inv.Pods[0].Status.Phase = core.PodRunning
	if inventoryKey(inv) != key {
		t.Fatal("status-only change invalidated metadata")
	}
	inv.Pods[0].Labels["app"] = "two"
	if inventoryKey(inv) == key {
		t.Fatal("selector change reused metadata")
	}
}

func TestDPUTargetsUseTheHostNodeRecordedInOVS(t *testing.T) {
	pod := func(name, node string, containers ...string) *core.Pod {
		p := &core.Pod{ObjectMeta: meta.ObjectMeta{Namespace: "ovn-kubernetes", Name: name}, Spec: core.PodSpec{NodeName: node}, Status: core.PodStatus{Phase: core.PodRunning}}
		for _, c := range containers {
			p.Spec.Containers = append(p.Spec.Containers, core.Container{Name: c})
		}
		return p
	}
	dpu := &Client{Core: fake.NewClientset(
		pod("ovnkube-node-dpu-a", "host0-dpu", "nb-ovsdb", "ovnkube-controller"),
		pod("ovnkube-node-dpu-b", "host1-dpu", "ovnkube-controller"),
		pod("ovnkube-node-dpu-c", "host2-dpu", "ovnkube-controller"),
		pod("ovnkube-control-plane", "dpu-cp", "ovnkube-cluster-manager"),
	)}
	var appctl []string
	c := Collector{DPU: dpu, Namespace: "ovn-kubernetes", MaxDetraces: 1}
	c.exec = func(_ context.Context, target Target, args []string) (string, error) {
		switch {
		case args[0] == "ovs-vsctl" && args[len(args)-1] == "external_ids:host-k8s-nodename":
			if target.Pod == "ovnkube-node-dpu-c" {
				return "", fmt.Errorf("no such key")
			}
			return "\"host0\"\n", nil
		case args[0] == "cat":
			return "3616\n", nil
		case args[0] == "ovs-appctl":
			appctl = append(appctl, args[2])
		}
		return `{"headings":["_uuid"],"data":[]}`, nil
	}
	targets, errs := c.dpuTargets(context.Background())
	want := Target{"ovn-kubernetes", "ovnkube-node-dpu-a", "ovnkube-controller"}
	if len(targets) != 1 || targets["host0"].ovn != want || targets["host0"].client != dpu || len(errs) != 2 {
		t.Fatal(targets, errs)
	}
	c.captureNode(context.Background(), "host0", targets["host0"], "inventory", nil)
	if len(appctl) == 0 || slices.ContainsFunc(appctl, func(s string) bool { return s != "/var/run/openvswitch/ovs-vswitchd.3616.ctl" }) {
		t.Fatal("appctl targets", appctl)
	}
}
