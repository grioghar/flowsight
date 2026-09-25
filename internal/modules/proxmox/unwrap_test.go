package proxmox

import (
	"encoding/json"
	"testing"
)

// The live API wraps every answer in {"data": ...}; pvesh (and the fixtures)
// do not. Both shapes must read the same.
func TestAgentAnswersReadWrappedAndBare(t *testing.T) {
	bare := []byte(`{"result":[{"hardware-address":"bc:24:11:00:00:01","ip-addresses":[{"ip-address":"192.168.1.9","ip-address-type":"ipv4"}]}]}`)
	wrapped := []byte(`{"data":` + string(bare) + `}`)
	for _, b := range [][]byte{bare, wrapped} {
		var r pveAgentNetworkResp
		if err := json.Unmarshal(unwrapData(b), &r); err != nil || len(r.Result) != 1 || r.Result[0].IPAddresses[0].IPAddress != "192.168.1.9" {
			t.Fatalf("agent network not read: %v %+v", err, r)
		}
	}
	var h pveAgentHostname
	if err := json.Unmarshal(unwrapData([]byte(`{"data":{"result":{"host-name":"docker"}}}`)), &h); err != nil || h.Result.HostName != "docker" {
		t.Fatalf("hostname: %v %+v", err, h)
	}
	if string(unwrapData([]byte(`{"data":null,"message":"denied"}`))) != `{"data":null,"message":"denied"}` {
		t.Fatal("a null data must not be unwrapped to nothing")
	}
}
