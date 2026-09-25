package proxmox

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// The first live poll deadlocked the module: the socket probe was called
// while the inventory lock was held and took the lock again, and every
// status call after that hung for ever. Swapping the inventory in and
// probing must never overlap, and status must answer right after a poll.
func TestStatusAnswersAfterAPollSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flowsight.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeclareModule("proxmox", map[string]any{"probe_sockets": false})
	m := &Module{ctx: &core.Context{Name: "proxmox", Config: cfg}}
	inv := &Inventory{Guests: []Guest{{VMID: 100, Type: "lxc", Name: "a"}}, Nodes: []Node{}}
	done := make(chan struct{})
	go func() {
		m.probeSockets(inv)
		m.setInventory(inv)
		m.mu.Lock()
		m.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("inventory swap deadlocked")
	}
}
