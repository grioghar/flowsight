package paths

import (
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func TestTalkersFoldFlowsIntoDevicesAndServices(t *testing.T) {
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().Unix()
	ins := `INSERT INTO flows(ts, src_ip, dst_ip, dst_port, proto, app, domain, bytes_in, bytes_out) VALUES(?,?,?,?,?,?,?,?,?)`
	rows := [][]any{
		{now - 60, "192.168.1.119", "1.1.1.1", 443, "udp", "QUIC", "one.one.one.one", 9000, 1200},
		{now - 120, "192.168.1.119", "1.1.1.1", 443, "udp", "QUIC", "one.one.one.one", 1000, 100},
		{now - 30, "192.168.1.119", "1.1.1.1", 53, "udp", "DNS", "", 300, 200},
		{now - 90, "192.168.1.53", "1.1.1.1", 53, "udp", "DNS", "", 100, 50},
		{now - 3*86400, "192.168.1.53", "1.1.1.1", 53, "udp", "DNS", "", 999999, 0}, // outside 24h
		{now - 10, "192.168.1.7", "8.8.8.8", 53, "udp", "DNS", "", 5, 5},            // another endpoint
	}
	for _, r := range rows {
		if err := st.Exec(ins, r...); err != nil {
			t.Fatal(err)
		}
	}
	m := &Module{ctx: &core.Context{Store: st}}
	tk := m.talkersFor("1.1.1.1", 24)
	if tk == nil || len(tk.Devices) != 2 {
		t.Fatalf("want 2 devices, got %+v", tk)
	}
	d := tk.Devices[0]
	if d.Addresses[0] != "192.168.1.119" || d.BytesIn != 10300 || d.Flows != 3 || len(d.Services) != 2 {
		t.Fatalf("busiest device wrong: %+v", d)
	}
	if d.Services[0].App != "QUIC" || d.Services[0].Domain != "one.one.one.one" || d.Services[0].Port != 443 || d.Services[0].Flows != 2 {
		t.Fatalf("services not folded: %+v", d.Services)
	}
	if tk.Devices[1].Addresses[0] != "192.168.1.53" || tk.Devices[1].BytesIn != 100 {
		t.Fatalf("old flows should be outside the window: %+v", tk.Devices[1])
	}
	if len(tk.Services) != 2 || tk.Services[0].App != "QUIC" || tk.Flows != 4 {
		t.Fatalf("summary wrong: %+v flows %d", tk.Services, tk.Flows)
	}
	if m.talkersFor("9.9.9.9", 24) != nil {
		t.Fatal("an endpoint nobody talked to should have no talkers")
	}
}
