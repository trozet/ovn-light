// SPDX-License-Identifier: Apache-2.0
package datapath

import "testing"

func TestMaskedIntersection(t *testing.T) {
	for _, tt := range []struct {
		key, a, b, want string
		ok              bool
	}{
		{"ipv4.dst", "10.1.2.0/255.255.255.0", "10.1.2.9", "10.1.2.9", true},
		{"ipv4.dst", "10.1.2.0/24", "10.1.3.9", "", false},
		{"tcp.dst", "0/0", "8080", "8080", true},
		{"tcp.dst", "80", "443", "", false},
		{"ipv6.dst", "fd00::/64", "fd00::12", "fd00::12", true},
		{"ct_state", "0x20/0x20", "0x21/0x21", "33/33", true},
	} {
		t.Run(tt.key+tt.a, func(t *testing.T) {
			got, ok := Intersect(tt.key, tt.a, tt.b)
			if ok != tt.ok || ok && got != tt.want {
				t.Fatalf("got %q,%t; want %q,%t", got, ok, tt.want, tt.ok)
			}
		})
	}
	if Exact("tcp.dst", "0/0") != "" {
		t.Fatal("wildcard became an exact port")
	}
}
func TestRecirculationComposition(t *testing.T) {
	raw := `ufid:a, recirc_id(0),in_port(4),ipv4(src=10.0.0.2,dst=10.0.0.0/24,proto=6),tcp(src=0/0,dst=0/0), packets:5, actions:ct(zone=1),recirc(0xa)
ufid:b, recirc_id(10),in_port(4),ipv4(dst=10.0.0.3,proto=6),tcp(dst=443), packets:5, actions:drop
ufid:c, recirc_id(10),in_port(4),ipv4(dst=10.1.0.3,proto=6),tcp(dst=80), packets:2, actions:drop`
	fs, errs := Parse(raw)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	paths := Reconstruct(fs)
	if len(paths) != 2 {
		t.Fatalf("paths=%+v", paths)
	}
	if len(paths[0].Flows) != 2 || paths[0].Identity["tcp.dst"] != "443" || !paths[0].Complete {
		t.Fatalf("composition: %+v", paths[0])
	}
	if paths[1].Complete || len(paths[1].Flows) != 1 {
		t.Fatal("incompatible continuation attached to ingress")
	}
}
func TestNATAndUnknownActions(t *testing.T) {
	m := map[string]string{"ipv4.dst": "10.96.0.2", "tcp.dst": "80", "ct_state": "0x20", "eth_type": "0x800"}
	n, w := Transform(m, "ct(zone=2,nat),recirc(1)")
	if _, ok := n["ipv4.dst"]; ok || len(w) == 0 {
		t.Fatal("NAT must discard pre-translation tuple and retain uncertainty")
	}
	n, w = Transform(m, "set(ipv4(dst=10.244.0.9)),recirc(3)")
	if n["ipv4.dst"] != "10.244.0.9" || len(w) != 0 {
		t.Fatal(n, w)
	}
	_, w = Transform(m, "clone(recirc(8)),recirc(9)")
	if len(w) == 0 {
		t.Fatal("conditional branch needs warning")
	}
	if Terminal("2,drop") != "" || Terminal("clone(drop),2") != "" {
		t.Fatal("forwarded traffic classified as an unconditional drop")
	}
}
func TestParseOffload(t *testing.T) {
	for _, tt := range []struct {
		provider string
		want     bool
	}{{"offloaded:yes, dp:tc", true}, {"dp:dpdk", false}, {"offloaded:no", false}} {
		f, e := ParseFlow("ufid:123, recirc_id(0),in_port(1), packets:7, bytes:42, " + tt.provider + ", actions:drop")
		if e != nil || f.Offloaded != tt.want || f.Packets != 7 {
			t.Fatal(f, e)
		}
	}
}
func TestCycleBounded(t *testing.T) {
	fs, _ := Parse("ufid:a, recirc_id(0),in_port(1), actions:recirc(1)\nufid:b, recirc_id(1),in_port(1), actions:recirc(1)")
	if len(Reconstruct(fs)) != 0 {
		t.Fatal("cycle should not invent a drop")
	}
}

func TestDropAfterConntrackCommit(t *testing.T) {
	commit := "ct(commit,zone=21,mark=0/0x41,label=0/0xffff00000000000000000000,nat(src))"
	for _, actions := range []string{commit, "set(skb_mark(0))," + commit, "ct_clear," + commit} {
		if Terminal(actions) != "drop" {
			t.Fatalf("missed implicit drop: %s", actions)
		}
	}
	for _, actions := range []string{commit + ",eth0", commit + ",recirc(1)", "clone(eth0)," + commit, "userspace(pid=1)," + commit, "ct(zone=21)", "ct(commit,table=1)", "drop(1),2"} {
		if Terminal(actions) != "" {
			t.Fatalf("invented unconditional drop: %s", actions)
		}
	}
	flows, _ := Parse("ufid:a,recirc_id(0),in_port(4),ipv4(src=10.0.0.2,dst=203.0.113.8),packets:3,actions:ct(zone=21,nat),recirc(1)\nufid:b,recirc_id(1),in_port(4),packets:3,actions:" + commit)
	paths := Reconstruct(flows)
	if len(paths) != 1 || len(paths[0].Flows) != 2 || paths[0].Original["ipv4.src"] != "10.0.0.2" {
		t.Fatal(paths)
	}
	if paths[0].Identity["ipv4.dst"] != "" {
		t.Fatal("pre-NAT destination was presented as known")
	}
}

func TestMaskedIngressPortAndSharedContinuation(t *testing.T) {
	fs, _ := Parse(`ufid:a,recirc_id(0),in_port(4),ipv4(src=10.0.0.1),packets:3,actions:recirc(1)
ufid:b,recirc_id(0),in_port(5),ipv4(src=10.0.0.2),packets:4,actions:recirc(1)
ufid:c,recirc_id(1),in_port(0/0),ipv4(src=0.0.0.0/0),packets:7,actions:drop`)
	paths := Reconstruct(fs)
	if len(paths) != 2 || len(paths[0].Flows) != 2 || len(paths[1].Flows) != 2 {
		t.Fatalf("masked continuation was not shared: %+v", paths)
	}
	if paths[0].Flows[1].ID != paths[1].Flows[1].ID {
		t.Fatal("shared counter identity was lost")
	}
}
func FuzzParse(f *testing.F) {
	f.Add("ufid:a,recirc_id(0),in_port(4),ipv4(src=10.0.0.1,dst=10.0.0.2), packets:1, actions:drop")
	f.Fuzz(func(t *testing.T, s string) {
		flows, _ := Parse(s)
		if len(flows) < 20 {
			_ = Reconstruct(flows)
		}
	})
}

func TestForwardedNamedPortsAndOutputRewriteOrder(t *testing.T) {
	flows, _ := Parse(`ufid:a,recirc_id(0),in_port(pod0),ipv4(src=10.0.0.1,dst=10.0.0.2),packets:10,actions:ct(zone=1),recirc(5)
ufid:b,recirc_id(5),in_port(pod0),ipv4(dst=10.0.0.2),packets:10,actions:pod1,set(ipv4(dst=10.0.0.3)),pod2`)
	paths := ReconstructTraffic(flows, "pod0", "pod1", "pod2")
	if len(paths) != 2 || paths[0].Verdict != "forward" || paths[0].Output != "pod1" || paths[0].Identity["ipv4.dst"] != "10.0.0.2" || paths[1].Identity["ipv4.dst"] != "10.0.0.3" {
		t.Fatal(paths)
	}
	if len(Reconstruct(flows)) != 0 {
		t.Fatal("forwarded packets became drops")
	}
	if len(ReconstructTraffic(flows)) != 0 {
		t.Fatal("unrecognized action was assumed to be an output")
	}
}

func TestPacketLengthBranchesRetainCounterScope(t *testing.T) {
	flows, _ := Parse(`ufid:a,recirc_id(0),in_port(1),ipv4(src=10.0.0.1,dst=10.0.1.0/24),packets:10,actions:check_pkt_len(size=1400,gt(drop),le(set(tunnel(src=192.0.2.1,dst=192.0.2.2)),geneve0))`)
	p := ReconstructTraffic(flows, "geneve0")
	if len(p) != 1 || p[0].Verdict != "forward" || !p[0].ConditionalCounter || p[0].Identity["tunnel.dst"] != "192.0.2.2" {
		t.Fatal(p)
	}
	if len(Reconstruct(flows)) != 0 {
		t.Fatal("conditional drop was assigned the parent counter")
	}
	flows, _ = Parse(`ufid:a,recirc_id(0),in_port(1),ipv4(src=10.0.0.1),packets:10,actions:check_pkt_len(size=1400,gt(userspace(pid=1)),le(recirc(8)))
ufid:b,recirc_id(8),in_port(1),packets:6,actions:2`)
	p = ReconstructTraffic(flows)
	if len(p) != 1 || len(p[0].Flows) != 2 || p[0].ConditionalCounter || p[0].Flows[1].Packets != 6 {
		t.Fatal(p)
	}
}

func TestDOCAOffloadEvidence(t *testing.T) {
	f, err := ParseFlow("ufid:a,recirc_id(0),in_port(1),packets:30,bytes:3000,partial_offload_packets:7,partial_offload_bytes:700,offloaded:partial,dp:ovs,actions:drop, dp-extra-info:miniflow_bits(1,2), dp-offload-info:'unsupported action, details'")
	if err != nil || f.Offloaded || f.OffloadStatus != "partial" || f.Provider != "ovs" || f.PartialPackets != 7 || f.PartialBytes != 700 || f.Actions != "drop" || f.OffloadInfo != "unsupported action, details" {
		t.Fatal(f, err)
	}
	f, err = ParseFlow("in_port(1),packets:1,bytes:64,dp:dpdk,actions:2")
	if err != nil || f.OffloadStatus != "unknown" {
		t.Fatal("DPDK alone is not hardware evidence", f, err)
	}
	if _, err = ParseFlow("in_port(1),partial_offload_packets:bad,actions:2"); err == nil {
		t.Fatal("invalid partial counter accepted")
	}
}

func TestIdenticalPacketLengthBranchesFollowedOnce(t *testing.T) {
	fs, errs := Parse(`ufid:a, recirc_id(0),in_port(4),ipv4(src=10.0.0.2,dst=10.0.0.3,proto=6),tcp(dst=80), packets:5, actions:check_pkt_len(size=1514,gt(ct(zone=1,nat),recirc(0x2)),le(ct(zone=1,nat),recirc(0x2)))
ufid:b, recirc_id(0x2),in_port(4),ipv4(proto=6), packets:5, actions:drop`)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if paths := Reconstruct(fs); len(paths) != 1 {
		t.Fatalf("paths=%d", len(paths))
	}
}

func TestHashSelectsANewDPHash(t *testing.T) {
	fs, errs := Parse(`ufid:a, recirc_id(0),dp_hash(0x1/0xf),in_port(4),ipv4(src=10.0.0.2,dst=10.96.0.10,proto=6),tcp(dst=80), packets:5, actions:hash(l4(0)),recirc(0x3)
ufid:b, recirc_id(0x3),dp_hash(0x2/0xf),in_port(4),ipv4(proto=6), packets:5, actions:drop`)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	paths := Reconstruct(fs)
	if len(paths) != 1 || !paths[0].Complete || len(paths[0].Warnings) > 0 {
		t.Fatalf("%+v", paths)
	}
}

func TestVLANPushAndPop(t *testing.T) {
	fs, errs := Parse(`ufid:a, recirc_id(0),in_port(pod),eth_type(0x0800),ipv4(src=10.0.0.2,dst=10.1.0.3,proto=6), packets:5, actions:push_vlan(vid=10,pcp=0),uplink
ufid:b, recirc_id(0),in_port(uplink),eth_type(0x8100),vlan(vid=10,pcp=0),encap(eth_type(0x0800),ipv4(src=10.1.0.3,dst=10.0.0.2,proto=6)), packets:5, actions:pop_vlan,pod`)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	paths := ReconstructTraffic(fs, "pod", "uplink")
	if len(paths) != 2 {
		t.Fatalf("%+v", paths)
	}
	for _, p := range paths {
		want := map[string]string{"uplink": "10", "pod": ""}[p.Output]
		if p.Identity["vlan.vid"] != want || len(p.Warnings) > 0 {
			t.Fatalf("output %s: vlan=%q warnings=%v", p.Output, p.Identity["vlan.vid"], p.Warnings)
		}
	}
}
