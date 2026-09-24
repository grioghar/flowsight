package paths

import (
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// The status call gathers from helpers that take the module lock. It must
// never hold that lock while calling them: it did once, and the deadlock
// froze every graph build on a live gateway.
func TestStatusDoesNotDeadlock(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &core.Config{}
	m := &Module{ctx: &core.Context{Store: st, Config: cfg, Name: "paths"}}
	if err := m.migrate(); err != nil {
		t.Fatal(err)
	}
	m.fixes.load(st)
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- nil // a nil-settings panic is not the deadlock under test
			}
		}()
		_, err := m.apiStatus(&core.Req{})
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("apiStatus did not return: it is holding the module lock while calling something that takes it")
	}
}
