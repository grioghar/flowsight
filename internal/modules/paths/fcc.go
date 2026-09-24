package paths

// The FCC National Broadband Map.
//
// The FCC publishes, twice a year, where every provider reports serving
// fixed and mobile broadband in the United States, by location and by
// technology. Its data API needs an account: a username and an API token
// from broadbandmap.fcc.gov, sent as headers. With them, FlowSight checks in
// monthly, records which release is current and what files it offers, and
// keeps the state-level provider summaries -- the per-location files are
// tens of gigabytes and have no place on a gateway. Without credentials
// nothing is asked.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const fccBase = "https://broadbandmap.fcc.gov/api/public/map"
const fccKV = "paths.fcc"

type fccState struct {
	On        bool   `json:"on"`
	AsOf      string `json:"as_of,omitempty"`
	Files     int    `json:"files,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"`
	Error     string `json:"error,omitempty"`
	Note      string `json:"note,omitempty"`
}

func (m *Module) fccCreds() (user, token string) {
	if m.ctx == nil {
		return "", ""
	}
	s := m.ctx.Settings()
	return strings.TrimSpace(core.Str(s, "fcc_username", "")), strings.TrimSpace(core.Str(s, "fcc_token", ""))
}

func (m *Module) fccGet(path string) ([]byte, error) {
	user, token := m.fccCreds()
	if user == "" || token == "" {
		return nil, fmt.Errorf("no FCC credentials")
	}
	req, err := http.NewRequest("GET", fccBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("username", user)
	req.Header.Set("hash_value", token)
	req.Header.Set("User-Agent", "FlowSight/"+m.version())
	req.Header.Set("Accept", "application/json")
	resp, err := safeClient(time.Minute).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fcc: %s: %s", resp.Status, firstLine(string(b)))
	}
	return b, nil
}

// fccJob checks in monthly: which release is current and what it offers.
func (m *Module) fccJob() error {
	user, token := m.fccCreds()
	st := fccState{On: user != "" && token != ""}
	if !st.On {
		m.mu.Lock()
		m.fcc = st
		m.mu.Unlock()
		return nil
	}
	var last fccState
	if m.ctx.Store.KVGet(fccKV, &last) && time.Since(time.Unix(last.CheckedAt, 0)) < 30*24*time.Hour && last.Error == "" {
		m.mu.Lock()
		m.fcc = last
		m.mu.Unlock()
		return nil
	}
	st.CheckedAt = time.Now().Unix()
	b, err := m.fccGet("/listAsOfDates")
	if err != nil {
		st.Error = err.Error()
	} else {
		var in struct {
			Data []struct {
				AsOf string `json:"as_of_date"`
				Type string `json:"data_type"`
			} `json:"data"`
		}
		_ = json.Unmarshal(b, &in)
		for _, d := range in.Data {
			if d.Type == "availability" && d.AsOf > st.AsOf {
				st.AsOf = d.AsOf
			}
		}
		if st.AsOf == "" && len(in.Data) > 0 {
			st.AsOf = in.Data[0].AsOf
		}
		if st.AsOf != "" {
			if fb, err := m.fccGet("/downloads/listAvailabilityData/" + strings.TrimSpace(st.AsOf)); err == nil {
				var files struct {
					Data []json.RawMessage `json:"data"`
				}
				_ = json.Unmarshal(fb, &files)
				st.Files = len(files.Data)
				_ = m.ctx.Store.KVSet(fccKV+".files", files.Data) // kept for the file browser
			} else {
				st.Error = err.Error()
			}
		}
		st.Note = "Release and file list recorded; state provider summaries are the next step once the account is confirmed."
	}
	_ = m.ctx.Store.KVSet(fccKV, st)
	m.mu.Lock()
	m.fcc = st
	m.mu.Unlock()
	return nil
}

// apiFCCCheck tests the credentials now.
func (m *Module) apiFCCCheck(r *core.Req) (any, error) {
	user, token := m.fccCreds()
	if user == "" || token == "" {
		return map[string]any{"ok": false, "error": "enter the FCC username and API token first"}, nil
	}
	_ = m.ctx.Store.KVSet(fccKV, fccState{}) // force a fresh check
	if err := m.fccJob(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	st := m.fcc
	m.mu.Unlock()
	return map[string]any{"ok": st.Error == "", "state": st}, nil
}

// apiFCCFiles lists what the current release offers, from the last check:
// a way to see the catalogue without pulling anything.
func (m *Module) apiFCCFiles(r *core.Req) (any, error) {
	var files []json.RawMessage
	m.ctx.Store.KVGet(fccKV+".files", &files)
	filter := strings.ToLower(strings.TrimSpace(r.Q("filter", "")))
	limit := r.QInt("limit", 200, 1, 20000)
	out := make([]json.RawMessage, 0, limit)
	for _, f := range files {
		if filter != "" && !strings.Contains(strings.ToLower(string(f)), filter) {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return map[string]any{"total": len(files), "shown": len(out), "files": out}, nil
}
