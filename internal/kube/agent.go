// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

const collectorURL = "https://ovn-light.ovn-light.svc:8443/v1/collection"

func localExec(ctx context.Context, args []string, limit int) (string, error) {
	// Named appctl targets open their pidfile read-write to check the lock.
	// Use the daemon's socket directly so its runtime directory stays read-only.
	if namesVswitchd(args) {
		raw, err := os.ReadFile("/var/run/openvswitch/ovs-vswitchd.pid")
		if err != nil {
			return "", err
		}
		ctl, err := vswitchdControl(string(raw))
		if err != nil {
			return "", err
		}
		args = append([]string{}, args...)
		args[2] = ctl
	}
	out, stderr := limitedBuffer{remaining: limit}, limitedBuffer{remaining: 4096}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", args[0], err, stderr.String())
	}
	return out.String(), nil
}

func namesVswitchd(args []string) bool {
	return len(args) >= 3 && args[0] == "ovs-appctl" && args[1] == "-t" && args[2] == "ovs-vswitchd"
}

func vswitchdControl(pidfile string) (string, error) {
	pid, err := strconv.ParseUint(strings.TrimSpace(pidfile), 10, 32)
	if err != nil || pid == 0 {
		return "", fmt.Errorf("invalid ovs-vswitchd pidfile")
	}
	return fmt.Sprintf("/var/run/openvswitch/ovs-vswitchd.%d.ctl", pid), nil
}

type agent struct {
	client           *http.Client
	collector        *Collector
	node, key, after string
	context          ovn.AnalysisContext
	previous         *model.Snapshot
}

func RunAgent(ctx context.Context, c *Collector, node string) error {
	if node == "" {
		return fmt.Errorf("NODE_NAME is required")
	}
	pem, err := os.ReadFile("/collector-ca/tls.crt")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid collector trust bundle")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	c.local = true
	a := agent{client: &http.Client{Transport: t, Timeout: 40 * time.Second}, collector: c, node: node}
	for ctx.Err() == nil {
		if err := a.poll(ctx); err != nil && ctx.Err() == nil {
			log.Printf("collector %s: %v", node, err)
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	}
	return nil
}
func (a *agent) request(ctx context.Context, method string, q url.Values, body []byte) (*http.Response, error) {
	token, err := os.ReadFile("/collector-identity/token")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, collectorURL+"?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	if method == "POST" {
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(req)
}

func (a *agent) poll(ctx context.Context) error {
	res, err := a.request(ctx, "GET", url.Values{"after": {a.after}, "key": {a.key}}, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == 204 {
		return nil
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("get collection request: %s", res.Status)
	}
	id, key := res.Header.Get("X-Collection-Round"), res.Header.Get("X-Context-Key")
	if id == "" || key == "" {
		return fmt.Errorf("collection request missing identity")
	}
	if key != a.key {
		raw, err := io.ReadAll(io.LimitReader(res.Body, contextLimit+1))
		if err != nil || len(raw) > contextLimit {
			return fmt.Errorf("cannot read collector context")
		}
		var x ovn.AnalysisContext
		if err = json.Unmarshal(raw, &x); err != nil {
			return err
		}
		a.context, a.key = x, key
	}
	local := Target{Pod: a.node}
	started := time.Now()
	var sample datapath.Sample
	n := a.collector.captureNode(ctx, a.node, nodeTargets{ovs: local, ovn: local}, key, &sample)
	report := ovn.Summarize(n, a.previous, a.context, sample)
	report.Collection.DurationMS = time.Since(started).Milliseconds()
	// Advance even if delivery fails. Replaying the old baseline after a lost
	// HTTP acknowledgement would count an accepted interval twice.
	a.previous = &model.Snapshot{Nodes: []model.NodeSnapshot{{Name: n.Name, Flows: n.Flows, Datapath: n.Datapath, FlowCapturedAt: n.FlowCapturedAt, CapturedAt: n.CapturedAt}}}
	a.after = id
	body, err := encodeSummary(report)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		res, err := a.request(ctx, "POST", url.Values{"round": {id}}, body)
		if err == nil {
			res.Body.Close()
			switch res.StatusCode {
			case 204:
				log.Printf("sent %d bytes for %d local flows, %d traffic groups", len(body), report.Summary.Flows, report.Collection.TrafficGroups)
				return nil
			case 409:
				return fmt.Errorf("collection round expired before acknowledgement")
			}
			err = fmt.Errorf("upload summary: %s", res.Status)
		}
		if attempt == 4 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1<<attempt)*500*time.Millisecond + rand.N(time.Second)):
		}
	}
	return nil
}

// A translation or an offload stage can belong to many paths. Bound each
// list before serializing the whole report to avoid expanding that repetition
// into one large temporary buffer.
func detailPrefix[T any](rows []T, budget int) []T {
	for i := range rows {
		raw, err := json.Marshal(rows[i])
		if err != nil || len(raw) > budget {
			return rows[:i]
		}
		budget -= len(raw)
	}
	return rows
}

func encodeSummary(n model.NodeSnapshot) ([]byte, error) {
	// Narrow evidence explicitly on overflow. A covered node with an incomplete
	// sample must not be used to infer a missing receiver or sustained offload.
	m := *n.Summary
	n.Summary = &m
	originalFindings, originalPaths := len(m.Findings), len(m.Paths)
	m.Findings = detailPrefix(m.Findings, nodeLimit/4)
	m.Paths = detailPrefix(m.Paths, nodeLimit/4)
	m.OmittedPaths = originalPaths - len(m.Paths)
	if len(m.Findings) < originalFindings || m.OmittedPaths != 0 {
		n.Collection.FlowComplete = false
		n.Errors = append(n.Errors, fmt.Sprintf("Detail budget omitted %d drop paths and %d offload paths.", originalFindings-len(m.Findings), m.OmittedPaths))
	}
	for pass := 0; ; pass++ {
		raw, err := json.Marshal(n)
		if err != nil {
			return nil, err
		}
		if len(raw) <= nodeLimit {
			b := compress(raw)
			if len(b) <= wireLimit {
				return b, nil
			}
		}
		n.Collection.FlowComplete = false
		switch pass {
		case 0:
			n.Errors = append(n.Errors, "Summary size limit reached. Detailed offload paths and excess drop evidence were omitted.")
			m.OmittedPaths = originalPaths
			m.Paths = nil
			m.Findings = m.Findings[:min(len(m.Findings), 16)]
		case 1:
			n.Errors = append(n.Errors, "Only collector totals are available for this oversized sample.")
			n = model.NodeSnapshot{Name: n.Name, CapturedAt: n.CapturedAt, FlowCapturedAt: n.FlowCapturedAt, Collection: n.Collection, Errors: n.Errors, Summary: &model.NodeSummary{Flows: m.Flows, Offloaded: m.Offloaded, OmittedPaths: originalPaths, OffloadNode: model.OffloadNode{Name: n.Name, State: "unknown"}}}
			n.Collection.TrafficGroups = 0
		default:
			return nil, fmt.Errorf("summary exceeds transport size limit")
		}
	}
}
