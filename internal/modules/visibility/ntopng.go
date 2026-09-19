package visibility

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ntopng is a minimal REST v2 client. ntopng answers {"rc":0,"rc_str":"OK","rsp":...};
// a non-zero rc or a login redirect is an error we can name.
type ntopng struct {
	base   string
	user   string
	pass   string
	token  string
	client *http.Client
}

var errAuth = errors.New("ntopng requires authentication: set ntopng_user/ntopng_password " +
	"(or an API token) in the visibility module settings, or start ntopng with -l=0")

func newNtopng(base, user, pass, token string, timeout time.Duration) *ntopng {
	return &ntopng{base: strings.TrimRight(base, "/"), user: user, pass: pass, token: token,
		client: &http.Client{Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // a 302 to login.lua must surface, not be followed
			}}}
}

func (n *ntopng) get(path string, q url.Values, out any) error {
	u := n.base + "/lua/rest/v2/get/" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if n.token != "" {
		req.Header.Set("Authorization", "Token "+n.token)
	} else if n.user != "" {
		req.SetBasicAuth(n.user, n.pass)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 401 || resp.StatusCode == 403 {
		return errAuth
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("ntopng %s: HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	var env struct {
		RC    int             `json:"rc"`
		RCStr string          `json:"rc_str"`
		Rsp   json.RawMessage `json:"rsp"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		if strings.Contains(string(body[:min(200, len(body))]), "<html") {
			return errAuth
		}
		return fmt.Errorf("ntopng %s: non-JSON reply", path)
	}
	if env.RC != 0 {
		return fmt.Errorf("ntopng %s: %s", path, env.RCStr)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Rsp, out)
}

// Loosely typed accessors: ntopng's JSON shapes shift between releases, so
// each field is looked up by a list of candidate names.

type obj map[string]any

func (o obj) sub(keys ...string) obj {
	for _, k := range keys {
		if m, ok := o[k].(map[string]any); ok {
			return obj(m)
		}
	}
	return nil
}

func (o obj) str(keys ...string) string {
	for _, k := range keys {
		switch v := o[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			if v {
				return "true"
			}
			return "false"
		}
	}
	return ""
}

func (o obj) num(keys ...string) float64 {
	for _, k := range keys {
		switch v := o[k].(type) {
		case float64:
			return v
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		case bool:
			if v {
				return 1
			}
		}
	}
	return 0
}

func (o obj) i64(keys ...string) int64 { return int64(o.num(keys...)) }

// list extracts rsp as a list, accepting {"data":[...]} and {"records":[...]}
// wrappers as well as a bare array.
func asList(raw json.RawMessage) []obj {
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil {
		out := make([]obj, 0, len(arr))
		for _, m := range arr {
			out = append(out, obj(m))
		}
		return out
	}
	var wrap map[string]json.RawMessage
	if json.Unmarshal(raw, &wrap) == nil {
		for _, k := range []string{"data", "records", "rows"} {
			if inner, ok := wrap[k]; ok {
				return asList(inner)
			}
		}
	}
	return nil
}

// hostIP takes a client/server object and returns its address, stripping
// the "@vlan" suffix ntopng appends.
func hostIP(h obj) string {
	ip := h.str("ip", "host", "address")
	if i := strings.Index(ip, "@"); i > 0 {
		ip = ip[:i]
	}
	return ip
}
