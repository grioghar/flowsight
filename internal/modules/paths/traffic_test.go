package paths

import (
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Endpoint traffic comes from the rollups: the same totals, keyed by time,
// and read once for every traced destination.
func TestTrafficToReadsTheRollups(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := &Module{ctx: &core.Context{Store: st}}
	if err := m.migrate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	b := now - now%300
	exec := func(q string, args ...any) {
		if err := st.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO path_runs(dst, ts, hops, complete) VALUES('1.1.1.1', ?, 5, 1)`, now)
	exec(`INSERT INTO path_runs(dst, ts, hops, complete) VALUES('9.9.9.9', ?, 5, 1)`, now)
	ins := `INSERT INTO rollup_dst(bucket,src_ip,dst_ip,dst_port,proto,bytes_in,bytes_out,flows) VALUES(?,?,?,443,'tcp',?,?,?)`
	exec(ins, b, "192.168.1.10", "1.1.1.1", 100, 10, 3)
	exec(ins, b-300, "192.168.1.11", "1.1.1.1", 50, 5, 2)
	exec(ins, b-3*86400, "192.168.1.10", "1.1.1.1", 999, 999, 9) // outside a 24h window
	exec(ins, b, "192.168.1.10", "8.8.8.8", 7, 7, 1)             // never traced
	in, out := m.trafficTo(24)
	if in["1.1.1.1"] != 150 || out["1.1.1.1"] != 15 {
		t.Fatalf("1.1.1.1: in %d out %d, want 150/15", in["1.1.1.1"], out["1.1.1.1"])
	}
	if _, ok := in["8.8.8.8"]; ok {
		t.Fatal("an untraced destination was counted")
	}
	if in["9.9.9.9"] != 0 {
		t.Fatal("a quiet destination has traffic")
	}
	in, _ = m.trafficTo(24 * 7)
	if in["1.1.1.1"] != 1149 {
		t.Fatalf("a week: %d, want 1149", in["1.1.1.1"])
	}
	if inside := m.insideFor("1.1.1.1", ""); inside == nil || inside.Addresses[0] != "192.168.1.10" {
		t.Fatalf("insideFor: %+v", inside)
	}
}
