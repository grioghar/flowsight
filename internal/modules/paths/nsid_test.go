package paths

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// A tiny CHAOS TXT responder, so the wire format is tested end to end.
func fakeChaosServer(t *testing.T, answer string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP:", err)
	}
	go func() {
		defer pc.Close()
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := buf[:n]
		resp := append([]byte(nil), q[:2]...)
		resp = append(resp, 0x84, 0x00) // response, authoritative
		resp = binary.BigEndian.AppendUint16(resp, 1)
		resp = binary.BigEndian.AppendUint16(resp, 1)
		resp = append(resp, 0, 0, 0, 0)
		resp = append(resp, q[12:]...) // echo the question
		resp = append(resp, 0xc0, 0x0c)
		resp = binary.BigEndian.AppendUint16(resp, 16)
		resp = binary.BigEndian.AppendUint16(resp, 3)
		resp = append(resp, 0, 0, 0, 0)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(answer)+1))
		resp = append(resp, byte(len(answer)))
		resp = append(resp, answer...)
		_, _ = pc.WriteTo(resp, addr)
	}()
	return pc.LocalAddr().String()
}

func TestChaosTXTRoundTrip(t *testing.T) {
	addr := fakeChaosServer(t, "DFW.cf.f.root-servers.org")
	host, port, _ := net.SplitHostPort(addr)
	// chaosTXT dials port 53; point it at the fake by dialing directly.
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	id := uint16(0x1234)
	msg := binary.BigEndian.AppendUint16(nil, id)
	msg = append(msg, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	msg = append(msg, 2, 'i', 'd', 6, 's', 'e', 'r', 'v', 'e', 'r', 0, 0, 16, 0, 3)
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseTXTAnswer(buf[:n], id)
	if err != nil || got != "DFW.cf.f.root-servers.org" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := parseTXTAnswer(buf[:n], 0x9999); err == nil {
		t.Fatal("a reply to another query must be rejected")
	}
}

func TestIdentifiersAreDecodedBySiteListThenByCode(t *testing.T) {
	m := &Module{}
	m.rootByID = map[string]rootSite{
		"groot-con2-1":              {Letter: "g", Town: "San Antonio", Country: "US", Lat: 29.42, Lon: -98.49},
		"dfw.cf.f.root-servers.org": {Letter: "f", Town: "Dallas", Country: "US", Lat: 32.78, Lon: -96.80},
	}
	h := Home{Lat: 39.18, Lon: -96.57, OK: true}
	if id := m.decodeIdentity("groot-con2-1", 30, h); !id.Located || id.Site != "San Antonio, US" || id.By != "root-servers.org" {
		t.Fatalf("published identifier: %+v", id)
	}
	// "con" would read as nothing sensible; the list knows better.
	if id := m.decodeIdentity("c01.MCI.eroot", 31, h); !id.Located || id.Lat < 39 || id.Lat > 40 || id.By == "root-servers.org" {
		t.Fatalf("airport code fallback (MCI = Kansas City): %+v", id)
	}
	if id := m.decodeIdentity("ns1.gb-lon.k.ripe.net", 20, h); id.Located {
		t.Fatalf("London at 20 ms from Kansas must not be believed: %+v", id)
	}
	if id := m.decodeIdentity("ns1.gb-lon.k.ripe.net", 132, h); !id.Located {
		t.Fatalf("London at 132 ms is fine: %+v", id)
	}
}
