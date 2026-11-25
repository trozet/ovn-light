// SPDX-License-Identifier: Apache-2.0
package datapath

import (
	"fmt"
	"slices"
	"strings"
)

type Path struct {
	Flows              []Flow
	Identity           map[string]string
	Original           map[string]string
	Warnings           []string
	Complete           bool
	Output             string
	Verdict            string
	ConditionalCounter bool
}

// Sample is shared by translation lookup and attribution for one flow dump.
type Sample struct {
	Flows  []Flow
	Paths  []Path
	Errors []string
}

func ReadSample(raw, ports string) Sample {
	flows, errs := Parse(raw)
	return Sample{Flows: flows, Errors: errs, Paths: ReconstructTraffic(flows, PortNames(ports)...)}
}

// Reconstruct follows compatible packet constraints rather than treating a
// recirculation ID as a connection ID. Limits bound adversarial/large dumps.
func Reconstruct(flows []Flow) []Path {
	return reconstruct(flows, false, nil)
}

// ReconstructTraffic also retains output paths. The output counter is the
// terminal flow's counter, not the sum of its recirculation predecessors.
func ReconstructTraffic(flows []Flow, portNames ...string) []Path {
	names := map[string]bool{}
	for _, name := range portNames {
		names[name] = true
	}
	return reconstruct(flows, true, names)
}

func reconstruct(flows []Flow, forward bool, names map[string]bool) []Path {
	byStage := map[string][]Flow{}
	for _, f := range flows {
		byStage[f.Recirc] = append(byStage[f.Recirc], f)
	}
	var paths []Path
	covered := map[string]bool{}
	const maxPaths = 4000
	visits := 0
	var walk func(Flow, Path, map[string]bool)
	walk = func(f Flow, p Path, seen map[string]bool) {
		visits++
		if len(paths) >= maxPaths || visits > 50000 {
			return
		}
		if seen[f.ID] || len(p.Flows) >= 24 {
			return
		}
		m, ok := Merge(p.Identity, f.Match)
		if !ok {
			return
		}
		p.Identity = m
		p.Flows = append(append([]Flow{}, p.Flows...), f)
		p.Warnings = append([]string{}, p.Warnings...)
		if len(p.Flows) == 1 {
			p.Original = clone(m)
		}
		if Terminal(f.Actions) == "drop" {
			p.Verdict = "drop"
			paths = append(paths, p)
			covered[f.ID] = true
			return
		}
		seen2 := map[string]bool{}
		for k, v := range seen {
			seen2[k] = v
		}
		seen2[f.ID] = true
		for _, branch := range actionBranches(f.Actions, 0) {
			q := p
			state, warnings := transform(m, branch.actions, names)
			q.Warnings = append(append([]string{}, p.Warnings...), warnings...)
			q.Identity = state
			if forward {
				for _, port := range outputs(branch.actions, names) {
					out := q
					out.Output, out.Verdict = port, "forward"
					out.Identity = outputIdentity(m, branch.actions, port, names)
					out.ConditionalCounter = branch.conditional
					if branch.conditional {
						out.Warnings = append(out.Warnings, "Conditional output: this counter measures input to the packet-length check; forwarding on this branch is unconfirmed.")
					}
					if len(paths) < maxPaths {
						paths = append(paths, out)
					}
					covered[f.ID] = true
				}
			}
			for _, id := range Recircs(branch.actions) {
				for _, next := range byStage[id] {
					if visits > 50000 || len(paths) >= maxPaths {
						return
					}
					// A downstream flow has its own counter after the branch. Its
					// counter does not include packets that took the other outcome.
					walk(next, q, seen2)
				}
			}
		}
	}
	for _, f := range flows {
		if f.Recirc == "0" {
			walk(f, Path{Identity: map[string]string{}, Complete: true}, map[string]bool{})
		}
	}
	for _, f := range flows {
		if len(paths) >= maxPaths {
			break
		}
		if !covered[f.ID] {
			p := Path{Flows: []Flow{f}, Identity: clone(f.Match), Original: clone(f.Match), Warnings: []string{"Ingress path is missing or incompatible; identity is incomplete."}}
			if Terminal(f.Actions) == "drop" {
				p.Verdict = "drop"
				paths = append(paths, p)
			} else if forward {
				for _, branch := range actionBranches(f.Actions, 0) {
					for _, port := range outputs(branch.actions, names) {
						p.Output, p.Verdict = port, "forward"
						p.Identity = outputIdentity(f.Match, branch.actions, port, names)
						p.ConditionalCounter = branch.conditional
						if branch.conditional {
							p.Warnings = append(p.Warnings, "Conditional output: the counter precedes the packet-length check.")
						}
						if len(paths) < maxPaths {
							paths = append(paths, p)
						}
					}
				}
			}
		}
	}
	if len(paths) >= maxPaths || visits > 50000 {
		for i := range paths {
			paths[i].Complete = false
			paths[i].Warnings = append(paths[i].Warnings, "Path limit reached; this snapshot is incomplete.")
		}
	}
	return paths
}

type actionBranch struct {
	actions     string
	conditional bool
}

// OVN uses packet-length checks around tunnel output and recirculation. Follow
// both branches, but never assign the parent counter to a confirmed drop.
func actionBranches(actions string, depth int) []actionBranch {
	if depth >= 4 {
		return []actionBranch{{actions: actions}}
	}
	parts := Split(actions)
	for i, a := range parts {
		if !strings.HasPrefix(a, "check_pkt_len(") || !strings.HasSuffix(a, ")") {
			continue
		}
		var out []actionBranch
		for _, choice := range Split(a[len("check_pkt_len(") : len(a)-1]) {
			if !(strings.HasPrefix(choice, "gt(") || strings.HasPrefix(choice, "le(")) || !strings.HasSuffix(choice, ")") {
				continue
			}
			expanded := append(append([]string{}, parts[:i]...), choice[3:len(choice)-1])
			expanded = append(expanded, parts[i+1:]...)
			for _, b := range actionBranches(strings.Join(expanded, ","), depth+1) {
				// Both outcomes often share the same actions; follow them once.
				if slices.ContainsFunc(out, func(o actionBranch) bool { return o.actions == b.actions }) {
					continue
				}
				b.conditional = true
				out = append(out, b)
				if len(out) >= 16 {
					return out
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []actionBranch{{actions: actions}}
}

func Transform(match map[string]string, actions string) (map[string]string, []string) {
	return transform(match, actions, nil)
}

// Later rewrites must not change the identity of an earlier output branch.
func outputIdentity(match map[string]string, actions, port string, names map[string]bool) map[string]string {
	var prefix []string
	for _, a := range Split(actions) {
		if out := outputs(a, names); len(out) > 0 && out[0] == port {
			break
		}
		prefix = append(prefix, a)
	}
	m, _ := transform(match, strings.Join(prefix, ","), names)
	return m
}
func transform(match map[string]string, actions string, names map[string]bool) (map[string]string, []string) {
	m := clone(match)
	var warnings []string
	for _, a := range Split(actions) {
		switch {
		case strings.HasPrefix(a, "recirc("):
		case strings.HasPrefix(a, "set(") && strings.HasSuffix(a, ")"):
			set := map[string]string{}
			flatten("", a[4:len(a)-1], set)
			for k, v := range set {
				if strings.Contains(v, "/") {
					delete(m, k)
					warnings = append(warnings, "Masked rewrite requires additional evidence: "+k)
				} else {
					m[k] = v
				}
			}
		case strings.HasPrefix(a, "ct("):
			delete(m, "ct_state")
			delete(m, "ct_mark")
			delete(m, "ct_label")
			delete(m, "ct_zone")
			if strings.Contains(a, "nat") {
				for _, k := range []string{"ipv4.src", "ipv4.dst", "ipv6.src", "ipv6.dst", "tcp.src", "tcp.dst", "udp.src", "udp.dst", "sctp.src", "sctp.dst"} {
					delete(m, k)
				}
				warnings = append(warnings, "Conntrack NAT may translate addresses or ports; only explicit matches after NAT identify the translated tuple.")
			}
		case strings.HasPrefix(a, "hash("):
			// Load-balancer group selection; the next stage matches the new dp_hash.
			delete(m, "dp_hash")
		case strings.HasPrefix(a, "push_vlan("):
			flatten("", "vlan"+a[len("push_vlan"):], m)
		case a == "pop_vlan":
			for k := range m {
				if strings.HasPrefix(k, "vlan.") {
					delete(m, k)
				}
			}
		case a == "ct_clear":
			for _, k := range []string{"ct_state", "ct_mark", "ct_label", "ct_zone"} {
				delete(m, k)
			}
		case strings.HasPrefix(a, "clone(") || strings.HasPrefix(a, "sample(") || strings.HasPrefix(a, "check_pkt_len("):
			warnings = append(warnings, "Conditional or cloned actions need packet evidence: "+a)
		default:
			if len(outputs(a, names)) == 0 {
				warnings = append(warnings, fmt.Sprintf("Action is not modeled during identity reconstruction: %s", a))
			}
		}
	}
	return m, warnings
}
