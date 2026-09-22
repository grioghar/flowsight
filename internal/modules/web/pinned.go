package web

// Certificate pinning: what can and cannot be done about it.
//
// A pinned client carries the certificate (or public key) it expects and
// refuses anything else. That is the whole point of pinning, and no proxy
// can talk it out of the refusal: only the client can, by trusting a
// different key. So FlowSight does not try to defeat pinning. It does the
// useful half instead: it recognises a pinned name from the way its bumped
// handshakes fail, stops decrypting that name, and relays it untouched, so
// the site keeps working while everything else stays inspected.
//
// Detection: a bumped session that carries no bytes and ends without a
// status (squid logs NONE_NONE/000 for a client that dropped the
// handshake) counts as a refusal. A name that refuses repeatedly inside the
// window is recorded, and from the next configuration apply it is spliced.
// Names are kept with the time they last refused, re-tested after a while
// (an application may stop pinning, or the failure may have been something
// else), and can be cleared or added by hand.

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const pinnedKV = "web.pinned"

// pinnedEntry is one name FlowSight stopped decrypting.
type pinnedEntry struct {
	Name     string `json:"name"`
	Failures int    `json:"failures"`
	First    int64  `json:"first"`
	Last     int64  `json:"last"`
	Manual   bool   `json:"manual"` // added by the operator, never retested
	Clients  int    `json:"clients,omitempty"`
}

type pinning struct {
	mu      sync.Mutex
	entries map[string]*pinnedEntry
	recent  map[string][]int64 // name -> refusal times inside the window
	clients map[string]map[string]bool
	held    map[string]heldBump // connections whose outcome is not known yet
	dirty   bool
}

// heldBump is a bumped CONNECT waiting to be judged. squid writes that line
// the same way whether the client accepted the certificate or refused it; the
// difference is whether any request follows on the same connection.
type heldBump struct {
	name, client string
	ts           int64
}

func newPinning() *pinning {
	return &pinning{entries: map[string]*pinnedEntry{}, recent: map[string][]int64{},
		clients: map[string]map[string]bool{}, held: map[string]heldBump{}}
}

// settleWait is how long a bumped connection is given to carry a request
// before it is judged a refusal. A client that accepts the certificate sends
// its first request in milliseconds; this is generous by three orders of
// magnitude so that a slow client is never called pinned.
const settleWait = 15 * time.Second

// holdBump records a bumped CONNECT whose outcome is not yet known.
func (m *Module) holdBump(client, cport, name string, ts int64) {
	if name == "" || m.pin == nil || !m.autoBypassEnabled() {
		return
	}
	m.pin.mu.Lock()
	m.pin.held[client+"|"+cport] = heldBump{name: name, client: client, ts: ts}
	m.pin.mu.Unlock()
}

// settleBump resolves a held connection: a request arrived inside it, so the
// client accepted the certificate FlowSight minted.
func (m *Module) settleBump(client, cport string, ok bool) {
	if m.pin == nil {
		return
	}
	key := client + "|" + cport
	m.pin.mu.Lock()
	h, waiting := m.pin.held[key]
	delete(m.pin.held, key)
	m.pin.mu.Unlock()
	if waiting {
		m.noteBumpResult(h.name, h.client, ok)
	}
}

// expireHeldBumps judges the connections that never carried a request. It runs
// from the supervise job, so a refusal is recorded within a cycle of it
// happening rather than never.
func (m *Module) expireHeldBumps() {
	if m.pin == nil {
		return
	}
	cut := time.Now().Add(-settleWait).Unix()
	m.pin.mu.Lock()
	var done []heldBump
	for key, h := range m.pin.held {
		if h.ts <= cut {
			done = append(done, h)
			delete(m.pin.held, key)
		}
	}
	m.pin.mu.Unlock()
	for _, h := range done {
		m.noteBumpResult(h.name, h.client, false)
	}
}

func (m *Module) loadPinned() {
	m.pin = newPinning()
	var list []pinnedEntry
	if m.ctx.Store.KVGet(pinnedKV, &list) {
		for i := range list {
			e := list[i]
			m.pin.entries[e.Name] = &e
		}
	}
	m.dropFalsePinned()
}

// dropFalsePinned clears the automatically detected entries once, because
// they were found with a test that counted a successful decryption as a
// refusal: squid logs a bumped CONNECT identically either way. Names that
// really do pin are detected again within minutes; names that never did stop
// being spliced for no reason. Entries added by hand are left alone.
func (m *Module) dropFalsePinned() {
	const flag = "web.pinned.settled_detection"
	var done bool
	if m.ctx.Store.KVGet(flag, &done) && done {
		return
	}
	m.pin.mu.Lock()
	var dropped int
	for name, e := range m.pin.entries {
		if !e.Manual {
			delete(m.pin.entries, name)
			dropped++
		}
	}
	m.pin.mu.Unlock()
	if dropped > 0 {
		m.savePinned()
		m.ctx.Log.Info("cleared automatically detected pinned names; they are found again as they refuse", "dropped", dropped)
	}
	_ = m.ctx.Store.KVSet(flag, true)
}

func (m *Module) savePinned() {
	m.pin.mu.Lock()
	out := make([]pinnedEntry, 0, len(m.pin.entries))
	for _, e := range m.pin.entries {
		out = append(out, *e)
	}
	m.pin.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	_ = m.ctx.Store.KVSet(pinnedKV, out)
}

// autoBypassEnabled reports the setting; on by default because a pinned site
// that cannot load is worse than a site that is not inspected.
func (m *Module) autoBypassEnabled() bool {
	return core.Bool(m.ctx.Settings(), "auto_bypass_pinned", true)
}

// noteBumpResult feeds one parsed log line to the detector. ok is false when
// the client refused the certificate FlowSight minted.
func (m *Module) noteBumpResult(name, client string, ok bool) {
	if name == "" || m.pin == nil || !m.autoBypassEnabled() {
		return
	}
	needed := core.Int(m.ctx.Settings(), "pinned_failures", 3)
	if needed < 1 {
		needed = 1
	}
	window := time.Duration(core.Int(m.ctx.Settings(), "pinned_window_minutes", 10)) * time.Minute
	now := time.Now()
	m.pin.mu.Lock()
	defer m.pin.mu.Unlock()
	if ok {
		// A handshake that completed clears the name's recent refusals and,
		// if it was only ever auto-detected, lets it go back to inspection.
		delete(m.pin.recent, name)
		if e := m.pin.entries[name]; e != nil && !e.Manual {
			delete(m.pin.entries, name)
			delete(m.pin.clients, name)
			m.pin.dirty = true
			m.ctx.Event("web", "no longer pinned: "+name+" completed an inspected handshake", map[string]any{"name": name})
		}
		return
	}
	cut := now.Add(-window).Unix()
	var keep []int64
	for _, t := range m.pin.recent[name] {
		if t >= cut {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now.Unix())
	m.pin.recent[name] = keep
	if m.pin.clients[name] == nil {
		m.pin.clients[name] = map[string]bool{}
	}
	if client != "" {
		m.pin.clients[name][client] = true
	}
	if len(keep) < needed {
		return
	}
	e := m.pin.entries[name]
	if e == nil {
		e = &pinnedEntry{Name: name, First: now.Unix()}
		m.pin.entries[name] = e
		m.pin.dirty = true
		m.ctx.Event("web", "pinned certificate detected: "+name+" is relayed without inspection", map[string]any{"name": name, "failures": len(keep)})
		_, _ = m.ctx.Store.AddFinding("web", "pinned", "info", name,
			"Pinned certificate: "+name+" is not inspected",
			"This name refused the inspection certificate, which is what certificate pinning does. FlowSight relays it untouched so it keeps working; its server name, timing and volume are still recorded. Only the client can change this.",
			"web:pinned:"+name)
	}
	e.Failures += 1
	e.Last = now.Unix()
	e.Clients = len(m.pin.clients[name])
}

// PinnedNames is the published service other modules read (the policy
// compiler folds it into every inspecting policy's bypass list).
func (m *Module) PinnedNames() []string { return m.pinnedNames() }

// pinnedNames returns the names to splice, ready for the proxy's ACL.
func (m *Module) pinnedNames() []string {
	if m.pin == nil || !m.autoBypassEnabled() {
		return nil
	}
	retest := time.Duration(core.Int(m.ctx.Settings(), "pinned_retest_hours", 168)) * time.Hour
	cut := time.Now().Add(-retest).Unix()
	m.pin.mu.Lock()
	defer m.pin.mu.Unlock()
	var out []string
	for name, e := range m.pin.entries {
		if !e.Manual && retest > 0 && e.Last < cut {
			// Old enough to be worth trying again; drop it and let the
			// detector decide anew.
			delete(m.pin.entries, name)
			delete(m.pin.recent, name)
			m.pin.dirty = true
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// flushPinned persists changes; called from the supervise job.
func (m *Module) flushPinned() {
	if m.pin == nil {
		return
	}
	m.pin.mu.Lock()
	d := m.pin.dirty
	m.pin.dirty = false
	m.pin.mu.Unlock()
	if d {
		m.savePinned()
		// The proxy configuration names these; the policy module reconciles
		// every minute and will rewrite it (its signature covers this list).
	}
}

// ---------------------------------------------------------------- API

func (m *Module) apiPinned(r *core.Req) (any, error) {
	m.pin.mu.Lock()
	out := make([]pinnedEntry, 0, len(m.pin.entries))
	for _, e := range m.pin.entries {
		out = append(out, *e)
	}
	m.pin.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	return map[string]any{"pinned": out, "auto_bypass": m.autoBypassEnabled(),
		"note": "A pinned client refuses any certificate but the one it expects, so these names cannot be decrypted by any proxy. FlowSight relays them untouched; server name, timing and volume are still recorded."}, nil
}

func (m *Module) apiPinnedSet(r *core.Req) (any, error) {
	var in struct {
		Name   string `json:"name"`
		Remove bool   `json:"remove"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	m.pin.mu.Lock()
	if in.Remove {
		delete(m.pin.entries, name)
		delete(m.pin.recent, name)
	} else {
		m.pin.entries[name] = &pinnedEntry{Name: name, Manual: true, First: time.Now().Unix(), Last: time.Now().Unix()}
	}
	m.pin.dirty = true
	m.pin.mu.Unlock()
	m.flushPinned()
	if in.Remove {
		_, _ = m.ctx.Store.ResolveFindings("web", map[string]bool{})
	}
	return map[string]any{"ok": true, "pinned": m.pinnedNames()}, nil
}
