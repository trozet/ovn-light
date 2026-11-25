// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Collector struct {
	Hub                   *Hub
	local                 bool
	Client                *Client
	DPU                   *Client
	RoutingEnabled        bool
	routingCache          map[string]routingCache
	Namespace, NBDB, SBDB string
	MaxDetraces           int
	Concurrency           int
	NodeSelector          string
	CacheTTL              time.Duration
	captureMu             sync.Mutex
	cacheMu               sync.Mutex
	cache                 map[string]nodeCache
	offloadCache          map[string]offloadCache
	exec                  func(context.Context, Target, []string) (string, error)
}
type nodeTargets struct {
	ovs, ovn, frr Target
	client        *Client // the cluster running the targets, if not Client
}

type traceCache struct{ Signature, Text string }
type nodeCache struct {
	QoS                                     model.QoSEvidence
	Key                                     string
	At                                      time.Time
	Bindings, Datapaths, LogicalFlows, ACLs []model.Row
	Traces                                  map[string]traceCache
	Bytes                                   int
}

// Status-only updates should not invalidate every node's OVN table cache.
// Labels, attachment identity and policy specs can change attribution.
func inventoryKey(inv model.Inventory) string {
	var versions []string
	add := func(v any) { b, _ := json.Marshal(v); versions = append(versions, string(b)) }
	for _, p := range inv.Pods {
		add([]any{"pod", p.UID, p.Namespace, p.Name, p.Spec.NodeName, p.Spec.HostNetwork, p.Status.HostIP, p.Status.PodIPs, p.Labels, p.Annotations["k8s.ovn.org/pod-networks"], p.Annotations["k8s.v1.cni.cncf.io/network-status"], p.DeletionTimestamp})
	}
	for _, p := range inv.Policies {
		add([]any{"policy", p.UID, p.Namespace, p.Spec})
	}
	for _, svc := range inv.Services {
		add([]any{"service", svc.UID, svc.Spec})
	}
	for _, n := range inv.Namespaces {
		add([]any{"namespace", n.UID, n.Name, n.Labels})
	}
	for kind, resources := range inv.Resources {
		if _, diagnostic := DiagnosticResources[kind]; diagnostic && kind != "networkqoses" && kind != "egressqoses" {
			continue
		}
		for _, r := range resources {
			add([]any{kind, r.GetUID(), r.GetNamespace(), r.GetName(), r.GetLabels(), r.GetAnnotations(), r.GetOwnerReferences(), r.Object["spec"]})
		}
	}
	sort.Strings(versions)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(versions, "\n"))))
}
func (c *Collector) cached(name, key string) nodeCache {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	ttl := c.CacheTTL
	if ttl <= 0 {
		ttl = time.Minute
	}
	if cached, ok := c.cache[name]; ok && cached.Key == key && time.Since(cached.At) < ttl {
		return cached
	}
	return nodeCache{Key: key, Traces: map[string]traceCache{}}
}
func (c *Collector) remember(name string, n nodeCache) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cache == nil {
		c.cache = map[string]nodeCache{}
	}
	delete(c.cache, name)
	if n.Bytes > 16<<20 {
		return
	}
	for {
		total := n.Bytes
		oldest := ""
		for k, v := range c.cache {
			total += v.Bytes
			if oldest == "" || v.At.Before(c.cache[oldest].At) {
				oldest = k
			}
		}
		if total <= 32<<20 {
			break
		}
		delete(c.cache, oldest)
	}
	c.cache[name] = n
}

func (c *Collector) Capture(ctx context.Context) (model.Snapshot, error) {
	c.captureMu.Lock()
	defer c.captureMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	s := model.Snapshot{Version: 1, CapturedAt: time.Now().UTC()}
	inv, err := c.Client.Inventory(ctx)
	if err != nil {
		return s, err
	}
	s.Inventory = inv
	key := inventoryKey(inv)
	selector, err := labels.Parse(c.NodeSelector)
	if err != nil {
		return s, fmt.Errorf("invalid collection node selector: %w", err)
	}
	selected := map[string]bool{}
	for _, node := range inv.Nodes {
		if selector.Matches(labels.Set(node.Labels)) {
			selected[node.Name] = true
		}
	}
	if c.NodeSelector != "" {
		s.Inventory.DiagnosticErrors["collectionScope"] = "Datapath collection is scoped to nodes matching " + c.NodeSelector
	}
	targets := map[string]nodeTargets{}
	for _, p := range inv.Pods {
		if p.Namespace != c.Namespace || p.Spec.NodeName == "" || p.DeletionTimestamp != nil || c.NodeSelector != "" && !selected[p.Spec.NodeName] {
			continue
		}
		t := targets[p.Spec.NodeName]
		for _, container := range p.Spec.Containers {
			target := Target{p.Namespace, p.Name, container.Name}
			switch container.Name {
			case "ovs-daemons", "ovs-vswitchd":
				t.ovs = target
			case "ovnkube-controller":
				t.ovn = target
			}
		}
		targets[p.Spec.NodeName] = t
	}
	if c.DPU != nil {
		dpus, errs := c.dpuTargets(ctx)
		for host, t := range dpus {
			if selected[host] {
				targets[host] = t
			}
		}
		if len(errs) > 0 {
			s.Inventory.DiagnosticErrors["dpuCollection"] = strings.Join(errs, "; ")
		}
	}
	if c.RoutingEnabled {
		for node, frr := range discoverFRR(inv) {
			if t, ok := targets[node]; ok {
				t.frr = frr
				targets[node] = t
			}
		}
	}
	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if c.Hub != nil {
		s.Nodes, err = c.Hub.collect(ctx, inv, selected, key)
		if err != nil {
			return s, err
		}
		var wg sync.WaitGroup
		slots := make(chan struct{}, concurrency)
		for i := range s.Nodes {
			n := &s.Nodes[i]
			if t := targets[n.Name].frr; t.Pod != "" {
				slots <- struct{}{}
				wg.Go(func() {
					defer func() { <-slots }()
					fr := c.captureRouting(n.Name, nodeTargets{frr: t}, func(t Target, args ...string) (string, error) {
						call, cancel := context.WithTimeout(ctx, 15*time.Second)
						defer cancel()
						return c.Client.execBounded(call, t, args, nil, 1<<20)
					})
					n.Routing.FRRTarget, n.Routing.Peers = fr.FRRTarget, fr.Peers
					n.Routing.Errors = append(n.Routing.Errors, fr.Errors...)
				})
			}
		}
		wg.Wait()
		sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Name < s.Nodes[j].Name })
		s.CapturedAt = time.Now().UTC()
		return s, nil
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	names := make([]string, 0, len(targets))
	for name, t := range targets {
		if t.ovs.Pod != "" || t.ovn.Pod != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	jobs := make(chan string, len(names))
	for _, name := range names {
		jobs <- name
	}
	close(jobs)
	snapshotBytes := 0
	// A fixed worker pool bounds both command concurrency and waiting goroutines.
	for range min(concurrency, len(names)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				var n model.NodeSnapshot
				if ctx.Err() != nil {
					n = model.NodeSnapshot{Name: name, CapturedAt: time.Now().UTC(), Errors: []string{"Collection deadline reached before this node could be inspected."}}
				} else {
					n = c.captureNode(ctx, name, targets[name], key, nil)
				}
				encoded, _ := json.Marshal(n)
				mu.Lock()
				if snapshotBytes+len(encoded) > 64<<20 {
					n = model.NodeSnapshot{Name: name, CapturedAt: n.CapturedAt, Collection: n.Collection, Errors: []string{"Snapshot size limit reached; this node's evidence was omitted."}}
					n.Collection.FlowComplete = false
				} else {
					snapshotBytes += len(encoded)
				}
				s.Nodes = append(s.Nodes, n)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Name < s.Nodes[j].Name })
	if len(s.Nodes) == 0 {
		return s, fmt.Errorf("no OVS/OVN pods found in namespace %s (expected ovs-daemons and ovnkube-controller containers)", c.Namespace)
	}
	s.CapturedAt = time.Now().UTC()
	return s, nil
}

func (c *Collector) captureNode(ctx context.Context, name string, t nodeTargets, key string, prepared *datapath.Sample) (n model.NodeSnapshot) {
	started := time.Now()
	defer func() { n.Collection.DurationMS = time.Since(started).Milliseconds() }()
	ctx, cancelNode := context.WithTimeout(ctx, 90*time.Second)
	defer cancelNode()
	n = model.NodeSnapshot{Name: name, CapturedAt: time.Now().UTC(), Detraces: map[string]string{}}
	vswitchd := ""
	execute := func(target Target, args ...string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if target.Pod == "" {
			return "", fmt.Errorf("no command target")
		}
		if n.Collection.Bytes >= 24<<20 {
			return "", fmt.Errorf("node collection byte budget reached")
		}
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		var out string
		var err error
		n.Collection.Commands++
		if vswitchd != "" && namesVswitchd(args) {
			args = append([]string{}, args...)
			args[2] = vswitchd
		}
		limit := min(8<<20, (24<<20)-n.Collection.Bytes)
		if c.local {
			out, err = localExec(call, args, limit)
		} else {
			client := c.Client
			if t.client != nil {
				client = t.client
			}
			out, err = c.execOn(call, client, target, args, limit)
		}
		n.Collection.Bytes += len(out)
		return out, err
	}
	run := func(target Target, args ...string) string {
		out, err := execute(target, args...)
		if err != nil {
			n.Errors = append(n.Errors, shortError(err))
		}
		return out
	}

	if t.ovs.Pod == "" {
		// OVS runs outside this pod's PID namespace, so ovs-appctl cannot
		// validate the pidfile. Address the control socket directly.
		t.ovs = t.ovn
		if !c.local && t.ovs.Pod != "" {
			vswitchd, _ = vswitchdControl(run(t.ovs, "cat", "/var/run/openvswitch/ovs-vswitchd.pid"))
		}
	}
	if t.ovn.Pod == "" {
		n.Errors = append(n.Errors, "No ovnkube-controller container; ACL attribution is unavailable.")
	}
	n.Flows = run(t.ovs, "ovs-appctl", "-t", "ovs-vswitchd", "dpctl/dump-flows", "-m")
	n.FlowCapturedAt = time.Now().UTC()
	n.Collection.FlowComplete = len(n.Errors) == 0 && n.Flows != ""
	n.Ports = run(t.ovs, "ovs-appctl", "-t", "ovs-vswitchd", "dpctl/show")
	for _, line := range strings.Split(n.Ports, "\n") {
		if strings.HasPrefix(line, "system@") || strings.HasPrefix(line, "netdev@") || strings.HasPrefix(line, "doca@") {
			n.Datapath = strings.TrimSpace(line)
			break
		}
	}
	table := func(target Target, args ...string) []model.Row {
		raw := run(target, args...)
		if raw == "" {
			return nil
		}
		rows, err := ovn.DecodeTable(raw)
		if err != nil {
			n.Errors = append(n.Errors, fmt.Sprintf("decode %s: %v", args[len(args)-1], err))
		}
		return rows
	}
	n.Interfaces = table(t.ovs, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=_uuid,name,ofport,external_ids,type,options,status,error,link_state,mtu,statistics,ingress_policing_rate,ingress_policing_burst", "list", "Interface")
	n.Offload = c.captureOffload(ctx, name, t.ovs, execute)
	key += fmt.Sprintf("/%v/%v", t.ovs, t.ovn)
	cached := c.cached(name, key)
	if !cached.At.IsZero() {
		n.Collection.MetadataCached = true
		for _, trace := range cached.Traces {
			cached.Bytes -= len(trace.Text) + len(trace.Signature)
		}
	} else {
		beforeErrors, beforeBytes := len(n.Errors), n.Collection.Bytes
		cached.Bindings = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,logical_port,datapath,tunnel_key,type,options", "list", "Port_Binding")
		cached.Datapaths = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,tunnel_key,external_ids", "list", "Datapath_Binding")
		cached.LogicalFlows = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,external_ids,match,actions", "list", "Logical_Flow")
		cached.ACLs = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+c.NBDB, "--format=json", "--columns=_uuid,external_ids,action,match,direction,priority", "list", "ACL")
		cached.QoS = captureQoS(t, c.NBDB, execute)
		cached.Bytes = n.Collection.Bytes - beforeBytes
		if len(n.Errors) == beforeErrors && ctx.Err() == nil && t.ovn.Pod != "" {
			cached.At = time.Now().UTC()
		}
	}
	n.QoS = cached.QoS
	n.Bindings, n.Datapaths, n.LogicalFlows, n.ACLs, n.MetadataAt = cached.Bindings, cached.Datapaths, cached.LogicalFlows, cached.ACLs, cached.At
	sample := datapath.ReadSample(n.Flows, n.Ports)
	if prepared != nil {
		*prepared = sample
	}
	flows, paths := sample.Flows, sample.Paths
	if len(sample.Errors) > 0 {
		n.Collection.FlowComplete = false
		n.Errors = append(n.Errors, sample.Errors...)
	}
	wanted := map[string]int{}
	localPods := map[string]bool{}
	for _, iface := range n.Interfaces {
		if ovn.Str(ovn.Map(iface["external_ids"])["iface-id-ver"]) != "" {
			localPods[ovn.Str(iface["name"])] = true
		}
	}
	for _, line := range strings.Split(n.Ports, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "port" && localPods[fields[2]] {
			localPods[strings.TrimSuffix(fields[1], ":")] = true
		}
	}
	for _, p := range paths {
		if p.Flows[len(p.Flows)-1].Packets == 0 {
			continue
		}
		if p.Verdict == "forward" {
			// A pod-facing output already identifies the destination. Remote
			// outputs need only the terminal translation for logical outport.
			if !localPods[p.Output] {
				last := p.Flows[len(p.Flows)-1]
				if wanted[last.ID] < 1 {
					wanted[last.ID] = 1
				}
			}
			continue
		}
		for _, f := range p.Flows {
			priority := 1
			if p.Verdict == "drop" {
				priority = 2
			}
			if wanted[f.ID] < priority {
				wanted[f.ID] = priority
			}
		}
	}
	var ids []string
	for id := range wanted {
		if !strings.HasPrefix(id, "synthetic-") {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if wanted[ids[i]] != wanted[ids[j]] {
			return wanted[ids[i]] > wanted[ids[j]]
		}
		return ids[i] < ids[j]
	})
	flowByID := map[string]datapath.Flow{}
	for _, f := range flows {
		flowByID[f.ID] = f
	}
	limit := c.MaxDetraces
	if limit <= 0 {
		limit = 128
	}
	traces := map[string]traceCache{}
	lookups, omitted := 0, 0
	for _, id := range ids {
		f := flowByID[id]
		match, _ := json.Marshal(f.Match)
		signature := string(match) + f.Actions
		if trace, ok := cached.Traces[id]; ok && trace.Signature == signature {
			n.Detraces[id] = trace.Text
			traces[id] = trace
			n.Collection.DetraceHits++
			continue
		}
		if lookups >= limit {
			omitted++
			continue
		}
		lookups++
		before := len(n.Errors)
		out := run(t.ovs, "ovs-appctl", "-t", "ovs-vswitchd", "ofproto/detrace", "ufid:"+id)
		if len(n.Errors) > before {
			err := n.Errors[len(n.Errors)-1]
			if strings.Contains(err, "not a valid command") || strings.Contains(err, "unknown command") {
				break
			}
		}
		if strings.Contains(out, "Cache was not found") || strings.Contains(out, "UFID was not found") {
			continue
		}
		n.Detraces[id] = out
		if len(out) > 0 && len(out) < 256<<10 && len(traces) < 256 {
			traces[id] = traceCache{Signature: signature, Text: out}
		}
		if ctx.Err() != nil {
			break
		}
	}
	if omitted > 0 {
		n.Errors = append(n.Errors, fmt.Sprintf("Translation budget reached; %d UFIDs have no translation evidence this poll.", omitted))
	}
	cached.Traces = traces
	if !cached.At.IsZero() {
		for _, trace := range traces {
			cached.Bytes += len(trace.Text) + len(trace.Signature)
		}
		c.remember(name, cached)
	}
	if ctx.Err() != nil {
		n.Errors = append(n.Errors, "Node collection did not complete: "+ctx.Err().Error())
	}
	if c.RoutingEnabled {
		n.Routing = c.captureRouting(name, t, execute)
	}
	return n
}

func (c *Collector) execOn(ctx context.Context, client *Client, t Target, args []string, limit int) (string, error) {
	if c.exec != nil {
		return c.exec(ctx, t, args)
	}
	return client.execBounded(ctx, t, args, nil, limit)
}

// dpuTargets maps each host node to the ovnkube-node pod on its DPU, using the
// host name that OVN-Kubernetes records in the DPU's Open_vSwitch table.
func (c *Collector) dpuTargets(ctx context.Context) (map[string]nodeTargets, []string) {
	pods, err := c.DPU.Core.CoreV1().Pods(c.Namespace).List(ctx, meta.ListOptions{})
	if err != nil {
		return nil, []string{"list DPU pods: " + shortError(err)}
	}
	out := map[string]nodeTargets{}
	var errs []string
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil || p.Status.Phase != core.PodRunning || !slices.ContainsFunc(p.Spec.Containers, func(c core.Container) bool { return c.Name == "ovnkube-controller" }) {
			continue
		}
		target := Target{p.Namespace, p.Name, "ovnkube-controller"}
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		raw, err := c.execOn(call, c.DPU, target, []string{"ovs-vsctl", "--timeout=10", "get", "Open_vSwitch", ".", "external_ids:host-k8s-nodename"}, 4096)
		cancel()
		host := strings.Trim(strings.TrimSpace(raw), `"`)
		switch {
		case err != nil:
			errs = append(errs, p.Spec.NodeName+": "+shortError(err))
		case out[host].ovn.Pod != "":
			errs = append(errs, fmt.Sprintf("%s: host %s is also served by %s", p.Spec.NodeName, host, out[host].ovn.Pod))
		default:
			out[host] = nodeTargets{ovn: target, client: c.DPU}
		}
	}
	return out, errs
}
