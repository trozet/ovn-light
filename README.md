# OVN-Light

**See what’s blocking. Review a change. Verify the connection.**

OVN-Light is an experimental Go console for OVN-Kubernetes network troubleshooting. It inspects OVS datapath flow caches, follows compatible recirculations, maps pod attachments to networks, and links cached OpenFlow translations to OVN ACL ownership. It proposes additive NetworkPolicies, MultiNetworkPolicies and ClusterNetworkConnect resources for review in the browser.

The name is an oven light: a way to see what is happening inside OVN while it is running.

![OVN-Light showing a real policy-denied connection in KIND](docs/images/dashboard.png)

## Features

- [Connection tracing](docs/connection-tracing.md): simulate pod or Service traffic, inspect policy decisions and logical stages, review an allowance, and run explicit TCP or DNS checks.

- Live collection from existing OVS/OVN containers without a packet sampler or changes to hardware offload configuration.
- Live topology filtered by network, with node/pod drill-down, independent source/receiver rates, bounded recent history, and selectable drop evidence.
- Hardware Offload page with per-stage evidence, DOCA conntrack directions, partial-offload deltas and persistent fallback issues. See [offload diagnostics and limitations](docs/offload.md).
- Drop issues group equivalent paths that share a counter, without adding their packet counts. Select individual evidence paths to inspect UFIDs, masks, recirculations, warnings and raw OpenFlow evidence.
- Pod and network identity, including primary UDNs and overlapping IP ranges. Filter by network, node, workload or policy.
- Namespace default-deny ACL attribution when the translation cache and OVN stage hints are available.
- NetworkPolicy or MultiNetworkPolicy proposals inferred from the observed attachment, with the affected network shown in review. Both ingress and egress are evaluated.
- EgressFirewall drop attribution and reviewed IP/port exceptions inserted before the matching deny rule, with namespace-wide scope, TCP verification and guarded rule rollback.
- Review affected pods and YAML, admission dry-run, apply, optional TCP verification, persistent change history and guarded rollback.
- Reviewed connections between two primary UDNs through ClusterNetworkConnect when its API is available.
- A self-contained web UI, offline snapshot replay and a clearly marked synthetic demo.

Flow caches are not packet histories. Missing or wildcarded fields remain unknown. A cached default-deny flow often does not identify a destination port; choose the intended connection in that case. Hardware offload visibility depends on the driver and device and is **not** validated by the KIND test. See [architecture and limitations](docs/architecture.md).

## Try the UI without a cluster

Requires Go 1.26 or newer.

```sh
go run ./cmd/ovn-light --demo
```

Open **http://127.0.0.1:8080**. Demo proposals can be reviewed and downloaded; they cannot be applied to a cluster.

## Deploy on an existing OVN-Kubernetes KIND cluster

Requires Go, Docker, KIND, kubectl, OpenSSL, and a working OVN-Kubernetes cluster. The manifests expect OVN in `ovn-kubernetes`, `ovs-daemons` and `ovnkube-controller` containers, local NB/SB database sockets, and a default storage class for the audit volume.

```sh
# Replace ovn with your KIND cluster name. The script preserves your current context.
./scripts/deploy-kind.sh ovn
kubectl --context kind-ovn -n ovn-light port-forward service/ovn-light 8080:8080
```

In another terminal, retrieve the token and paste it into the login screen:

```sh
kubectl --context kind-ovn -n ovn-light get secret ovn-light-auth \
  -o jsonpath='{.data.token}' | base64 -d
```

The deployment enables reviewed writes. To run read only, remove `--enable-writes`, the `create`/`delete` verbs for NetworkPolicy, MultiNetworkPolicy and ClusterNetworkConnect, and the `patch` verb for EgressFirewall in `deploy/ovn-light.yaml`. The server uses `pods/exec` for on-demand diagnostics and optional FRR inspection. The DaemonSet has its own service account and reads local OVS sockets.

### Generate a denied connection

```sh
kubectl --context kind-ovn apply -f examples/denied-traffic.yaml
```

The example continuously attempts TCP/8080 from `client` to `server`, while `isolate-server` denies ingress. Both workloads run on the same node to make the first inspection straightforward.

1. Wait for the pods to be ready. Refresh the console and search for `ovn-light-demo`.
2. Inspect the drop path and ACL evidence.
3. Choose **Review a scoped allow rule**, or **Choose the intended connection** when the port is wildcarded. Select client → server, TCP/8080.
4. Review the YAML and matching pods, acknowledge the scope, and apply.
5. Use **Verify TCP connection**. The example grants probe permission only in its namespace.
6. Use **Roll back created resources** to remove the allowance. The original deny policy is preserved.

If the port is unknown and you intend to allow every TCP port, select **TCP** and
check **All TCP ports** in the connection form. The proposal keeps the selected
network and workload selectors, and its review explicitly lists the broader port
scope. An empty port field alone never means all ports. After applying, choose a
known listening port for **Verify selected TCP port**; success verifies only that
port, not the whole allowance. The same option supports UDP and SCTP policies,
with application tests required for verification.

For a masked source address, drop evidence shows the known node and source
subnet, plus candidate pods on the candidate network. Recent outgoing activity
is highlighted separately. **Review with this candidate** selects your intended
sender explicitly; it does not turn the candidate into a confirmed source.

An API write is not a successful connectivity test. A disappearing cache entry is not considered success either.

### Run locally against a cluster

```sh
export OVN_LIGHT_TOKEN="$(openssl rand -hex 32)"
go run ./cmd/ovn-light --context kind-ovn --enable-writes --data-dir .data
```

Print `$OVN_LIGHT_TOKEN` in your own terminal to log in. Omit `--enable-writes` for read-only operation. Use `--kubeconfig /path/to/config` when needed.

When OVN-Kubernetes runs in DPU mode, each host's OVS and OVN databases run
on its DPU, in a separate DPU cluster. Add that cluster's credentials:

```sh
go run ./cmd/ovn-light --kubeconfig host.conf --dpu-kubeconfig dpu.conf
```

The server finds the `ovnkube-controller` pods in the DPU cluster and maps each
DPU to its host through the `external_ids:host-k8s-nodename` value that
OVN-Kubernetes sets in the DPU's OVS. Pods, policies and proposals still come
from the host cluster. DPU collection runs from the server, so it cannot be
combined with `--daemonset-collectors`. Connection tracing and on-demand
diagnostics still run against the host cluster and do not reach the DPU yet.

### Capture and replay

```sh
go run ./cmd/ovn-light capture --context kind-ovn --output /tmp/ovn-light.json
go run ./cmd/ovn-light --snapshot /tmp/ovn-light.json
```

Snapshots contain workload metadata, policies and network topology. Treat them as cluster diagnostic data. Captures are written with mode `0600`.

## Live traffic topology

Open **Topology**, choose a network, and select a node to explore its pods. The
view ranks directed links by the highest observed rate at either end; filter to drops or unobserved
receipts, choose a recent window, and limit the number of links on screen.
Pods are grouped by their Kubernetes node. Selecting a link shows protocol/port
groups, separate source and receiver counters, rate history, and observation
coverage. When pod identity is incomplete, observations are grouped by network
and node direction with a **Pod match unconfirmed** label. Each observation keeps
its own counters and evidence; grouping never selects a pod for a policy proposal.
Drop details lead into the existing policy review workflow.

Two comparable captures are needed for rates. The first capture only establishes
a baseline. Green means corresponding activity was observed at both ends; red
marks measured drops; amber means receipt was not observed. Grey includes shared
counters, incomplete reconstruction and stale collection. An absent receiver
record does not establish packet loss. A counter before an OVN packet-length
check is labeled as branch input, not confirmed tunnel transmission. Wildcarded
subnet destinations remain unresolved pods even if only one current pod matches.

`examples/topology.yaml` creates a continuously active client and server on
separate nodes, initially denied by NetworkPolicy. It requires two schedulable
nodes; it tolerates the KIND control-plane taint. Review client → server on the
default network, TCP/8080, to allow the connection and observe forwarded traffic.

The KIND deployment runs one DaemonSet collector per Linux node. Every 30 seconds
after the previous round finishes, each collector reads its local OVS datapath,
reconstructs paths, and computes counter deltas. It sends a compressed summary
over HTTPS. Dashboard refreshes share this collection pipeline. The Collectors
page shows the local command bytes, uploaded bytes, traffic groups and coverage
for each node. The central server keeps up to 2,000 traffic groups and 60 rounds
over ten minutes. Standalone `capture` still supports a full raw diagnostic snapshot.
See [collection and scaling](docs/architecture.md#topology-and-scaling).

The **Run traffic test** button on Hardware Offload and topology links lets you choose a suite test, pod or ClusterIP path, and endpoint nodes when the optional TFT runner is installed. See [traffic tests](docs/traffic-tests.md).

## Traffic history with Loki

Open **History → Yesterday → Drops** to find traffic by network, pod, IP or policy name. Expand a result to see the workloads, the counter interval and the denying OVN ACL captured during collection. For a namespace default deny, the record includes the policies that selected the affected pod in that direction.

History is opt-in. The central server can write to an existing Loki instance. The two-node KIND example provides a single Loki pod capped at 256 MiB with 72-hour retention. See [Loki configuration, coverage and demo setup](docs/history.md).

## UDNs and network connections

Proposals opened from a drop keep its observed network fixed. The server infers the policy type from the actual pod attachment and records the scope in the proposal:

| Attachment | Proposed policy | Network scope |
| --- | --- | --- |
| CDN when primary | NetworkPolicy | Implicitly the namespace's primary network |
| Primary UDN or CUDN | NetworkPolicy | Implicitly the namespace's primary network |
| Secondary OVN network | MultiNetworkPolicy | Explicit `k8s.v1.cni.cncf.io/policy-for` NAD reference |

A regular NetworkPolicy has no network selector. Its `ovn-light.io/network` annotation is audit metadata, not an enforcement mechanism. MultiNetworkPolicy uses OVN's [policy-for targeting](https://ovn-kubernetes.io/1.4/features/multiple-networks/multi-network-policies/). Proposals evaluate only policies affecting the selected network; different NADs referring to the same OVN network are correlated. The CDN infrastructure attachment in a primary UDN namespace is not treated as a secondary network.

Secondary proposals require the MultiNetworkPolicy API, OVN-managed subnets and enabled OVN multi-network-policy enforcement. Existing applicable MultiNetworkPolicies must declare `policyTypes`; missing directions are not guessed. IPAM-less/DHCP selectors and automatic secondary-interface verification are not supported. A new connection review, or a drop with unresolved network identity, requires an explicit network choice.

`examples/secondary-network.yaml` provides two pods with separate CDN and secondary-network deny policies. This allows checking that a secondary allowance preserves primary-network isolation.

`examples/user-defined-networks.yaml` provides two disposable primary UDNs and workloads. See [validation and reproduction](docs/testing.md) for the tested workflow and cluster prerequisites.

**Networks → Connect networks** generates a ClusterNetworkConnect for two primary UDNs. Choose a connect subnet from your address plan. The planner rejects known overlap and requires selectors that match exactly the chosen networks in current inventory. ClusterUserDefinedNetworks need suitable existing labels. The UI never silently labels or rewrites a network. Cross-network NetworkPolicy proposals are not supported.

## External traffic and EgressFirewall

An attributed EgressFirewall drop offers **Review an EgressFirewall exception**.
OVN-Light identifies the namespace, firewall and zero-based ACL rule index, then
evaluates the current rules in order. Supply an exact external IP, protocol and
port when the flow cache leaves them wildcarded. A manual review is also available
under **Review a connection → Review external EgressFirewall traffic**.

The proposal inserts an Allow for one `/32` (IPv4) or `/128` (IPv6) and one port
immediately before the matching Deny. Review shows the current and proposed
firewalls and the insertion position. **The allowance affects all current and
future pods in the namespace on the default network**, not just the source pod.
This is an edit to an existing firewall, not an additive NetworkPolicy.

Apply performs admission dry-run and an atomic JSON Patch that tests the reviewed
UID and original spec. **Remove inserted allow rule** keeps the firewall itself
and restores its original rule order; later spec edits or replacement block
rollback. TCP verification connects from the selected source pod to the external
IP and port. The deployment needs `patch` permission on EgressFirewalls.

This action currently supports the primary CDN and CIDR rules. It declines UDNs,
secondary networks, conflicting source egress NetworkPolicies, applicable
administrative policies and earlier DNS/node-selector rules whose matching cannot
be established. It does not infer domain names from IPs, resolve DNS on behalf of
the workload, or create a second firewall. `examples/egress-firewall.yaml` provides
an isolated namespace for exercising this workflow.

## Routing, uplinks, EgressIP and administrative policies

**Routing** displays node → uplink → BGP peer paths, filterable by network and
node. Inspect a peer to see which PodNetwork or EgressIP prefixes are configured
and which FRR actually reports as advertised. Uplink details include the host
interface, OVS bridge, VRF, addresses, gateways and controller conditions.

**EgressIP** shows selected pods, assigned egress nodes and exact OVN SNAT
associations, with separate traffic observations where the datapath identifies
them. Multiple assignments and incomplete evidence stay explicit. ANP/BANP drops
show their policy and rule in **Issues**, including priority and the current rule;
they do not offer an ineffective ordinary NetworkPolicy fix for ANP Deny.

These are read-only integrations. See [routing evidence and setup](docs/routing.md)
for FRR permissions, collection limits, missing APIs and validation coverage.

## Access and deployment model

This is an administrator tool. The token grants access to the server’s service account; it does **not** impersonate the browser user’s Kubernetes identity. Use ClusterIP plus `kubectl port-forward`. An internet-facing deployment needs a TLS/authentication proxy and an appropriate authorization design.

The collector executes fixed, read-only commands. Kubernetes `pods/exec` is nevertheless a powerful permission. The API accepts connection intents, not arbitrary commands or manifests. Applied objects must come from stored, unexpired proposals. Rollback checks the recorded UID, owner annotation, spec hash and resource version before deleting.

For OpenShift, set `--ovn-namespace=openshift-ovn-kubernetes`, change the collector Role/RoleBinding namespace, and adapt the security context to the namespace’s SCC-assigned UID/group range. Container names and DB addresses may differ. KIND is the initial deployment target; an OpenShift operator and console plugin are not included.

## Development

```sh
make test   # Go tests with the race detector
make check  # go vet and JavaScript syntax check
make build  # bin/ovn-light
make image  # static binary in a scratch image; override IMAGE=... as needed
```

Collection, reconstruction, policy planning and the backend are Go. The embedded UI uses HTML, CSS and plain JavaScript, with no frontend build step or CDN. Optional browser checks use Playwright: run the demo, then `node scripts/browser-smoke.cjs` with Playwright installed in your development environment.

GitHub Actions runs Go race/vet checks, browser tests, and isolated KIND integration lanes covering CDN, primary UDN and ClusterNetworkConnect, secondary MultiNetworkPolicy, EgressFirewall, cross-node topology, ANP/BANP, EgressIP failover, BGP/uplinks, QoS and Loki history. Each deploys OVN-Kubernetes and OVN-Light and checks the corresponding evidence against real enforcement, traffic or routing state. Policy lanes exercise proposal/apply/rollback through the API. See [CI and local reproduction](docs/testing.md#continuous-integration).

Licensed under Apache-2.0. See [LICENSE](LICENSE).

See [QoS inspection and reviewed changes](docs/qos.md) and [topology navigation and scale limits](docs/topology-navigation.md).
