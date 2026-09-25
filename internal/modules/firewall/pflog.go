package firewall

// The firewall's own account of what the policy rules matched. pf writes a
// record to pflog for every packet a "log" rule matches, and OPNsense's
// filterlog turns those into text lines in /var/log/filter/latest.log:
// rule number, anchor, action, direction, addresses and ports. Counters say
// how many packets a rule matched; this says which ones. Only lines from the
// flowsight/policy anchor are kept, and the rule number is turned back into
// the rule's label, which names the policy.

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const hitsSchema = `CREATE TABLE IF NOT EXISTS policy_hits (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    policy TEXT, label TEXT, action TEXT, dir TEXT, iface TEXT, proto TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER
);
CREATE INDEX IF NOT EXISTS policy_hits_ts ON policy_hits(ts);
CREATE INDEX IF NOT EXISTS policy_hits_policy ON policy_hits(policy, ts);`

// Hit is one logged packet that matched a policy rule.
type Hit struct {
	TS      int64  `json:"ts"`
	Policy  string `json:"policy"`
	Label   string `json:"label"`
	Action  string `json:"action"`
	Dir     string `json:"dir"`
	Iface   string `json:"iface"`
	Proto   string `json:"proto"`
	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
}

// logLine is one filterlog record, whatever ruleset it came from.
type logLine struct {
	TS                int64
	RuleNr, SubRuleNr int
	Anchor, Iface     string
	Reason, Action    string
	Dir               string
	IPv               int
	Proto, Src, Dst   string
	SrcPort, DstPort  int
}

var ruleNrRe = regexp.MustCompile(`^@(\d+)\s`)

// parseFilterlog reads one line of OPNsense's filter log. The syslog prefix
// varies between formats, so the record is the last whitespace-separated
// field with the commas of a filterlog CSV, and the time comes from the
// RFC 5424 timestamp when there is one.
func parseFilterlog(line string, now time.Time) (logLine, bool) {
	var l logLine
	fields := strings.Fields(line)
	csv := ""
	for i := len(fields) - 1; i >= 0; i-- {
		if strings.Count(fields[i], ",") >= 8 {
			csv = fields[i]
			break
		}
	}
	if csv == "" {
		return l, false
	}
	f := strings.Split(csv, ",")
	if len(f) < 9 {
		return l, false
	}
	l.TS = now.Unix()
	if len(fields) > 1 {
		if t, err := time.Parse(time.RFC3339, fields[1]); err == nil {
			l.TS = t.Unix()
		} else if len(fields) > 2 {
			if t, err := time.Parse("Jan 2 15:04:05 2006", fields[0]+" "+fields[1]+" "+fields[2]+" "+strconv.Itoa(now.Year())); err == nil {
				l.TS = t.Unix()
			}
		}
	}
	l.RuleNr, _ = strconv.Atoi(f[0])
	l.SubRuleNr = -1
	if f[1] != "" {
		l.SubRuleNr, _ = strconv.Atoi(f[1])
	}
	l.Anchor, l.Iface, l.Reason, l.Action, l.Dir = f[2], f[4], f[5], f[6], f[7]
	l.IPv, _ = strconv.Atoi(f[8])
	var rest []string
	switch l.IPv {
	case 4:
		// tos, ecn, ttl, id, offset, flags, protonum, protoname, length, src, dst
		if len(f) < 20 {
			return l, false
		}
		l.Proto, l.Src, l.Dst = f[16], f[18], f[19]
		rest = f[20:]
	case 6:
		// class, flowlabel, hlim, protoname, protonum, length, src, dst
		if len(f) < 17 {
			return l, false
		}
		l.Proto, l.Src, l.Dst = f[12], f[15], f[16]
		rest = f[17:]
	default:
		return l, false
	}
	if (l.Proto == "tcp" || l.Proto == "udp") && len(rest) >= 2 {
		l.SrcPort, _ = strconv.Atoi(rest[0])
		l.DstPort, _ = strconv.Atoi(rest[1])
	}
	return l, true
}

// policyOfLabel turns "flowsight:<policy>:<kind>" into the policy's name.
func policyOfLabel(label string) string {
	if !strings.HasPrefix(label, "flowsight:") {
		return ""
	}
	rest := strings.TrimPrefix(label, "flowsight:")
	if i := strings.LastIndex(rest, ":"); i > 0 {
		return rest[:i]
	}
	return rest
}

// ruleLabels maps the policy anchor's rule numbers to their labels, from
// pfctl's numbered listing; cached briefly since the log is read often.
func (m *Module) ruleLabels() map[int]string {
	m.mu.Lock()
	if m.labelsAt.Add(30*time.Second).After(time.Now()) && m.labels != nil {
		out := m.labels
		m.mu.Unlock()
		return out
	}
	m.mu.Unlock()
	out := map[int]string{}
	text, err := m.pfctl("-a", rootAnchor+"/policy", "-vvsr")
	if err == nil {
		for _, l := range strings.Split(text, "\n") {
			t := strings.TrimSpace(l)
			mm := ruleNrRe.FindStringSubmatch(t)
			if mm == nil {
				continue
			}
			n, _ := strconv.Atoi(mm[1])
			if lm := labelRe.FindStringSubmatch(t); lm != nil {
				out[n] = lm[1]
			}
		}
	}
	m.mu.Lock()
	m.labels, m.labelsAt = out, time.Now()
	m.mu.Unlock()
	return out
}

func (m *Module) logPath() string {
	return strings.TrimSpace(core.Str(m.ctx.Settings(), "filter_log", "/var/log/filter/latest.log"))
}

// readLog picks up where the last read stopped, follows a rotated file from
// its start, and keeps the lines that belong to the policy anchor.
func (m *Module) readLog() error {
	path := m.logPath()
	if path == "" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		m.mu.Lock()
		m.logErr = err.Error()
		m.mu.Unlock()
		return nil // no log here is not a fault of ours
	}
	fh, err := os.Open(path)
	if err != nil {
		m.mu.Lock()
		m.logErr = err.Error()
		m.mu.Unlock()
		return nil
	}
	defer fh.Close()
	m.mu.Lock()
	if !m.logStarted {
		// Where the previous process stopped, so a restart neither replays
		// the file (every hit twice) nor skips what arrived meanwhile.
		m.logOff, m.logSize = m.loadLogPos()
		m.logStarted = true
	}
	off := m.logOff
	if m.logSize > st.Size() || off > st.Size() {
		off = 0 // rotated: from the start
	}
	m.logErr = ""
	m.mu.Unlock()
	if _, err := fh.Seek(off, io.SeekStart); err != nil {
		return err
	}
	labels := m.ruleLabels()
	now := time.Now()
	rd := bufio.NewReaderSize(fh, 256<<10)
	var hits []Hit
	lines, unknown := 0, 0
	for {
		line, err := rd.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			off += int64(len(line))
			lines++
			// filterlog names the leaf anchor ("policy"), not the full path.
			if strings.Contains(line, ",policy,") {
				if l, ok := parseFilterlog(line, now); ok && isPolicyAnchor(l.Anchor) {
					n := l.SubRuleNr
					if n < 0 {
						n = l.RuleNr
					}
					label, found := labels[n]
					if !found {
						label, found = labels[l.RuleNr]
					}
					if !found {
						unknown++
					}
					hits = append(hits, Hit{TS: l.TS, Policy: policyOfLabel(label), Label: label, Action: l.Action, Dir: l.Dir,
						Iface: l.Iface, Proto: l.Proto, SrcIP: l.Src, SrcPort: l.SrcPort, DstIP: l.Dst, DstPort: l.DstPort})
				}
			}
		}
		if err != nil {
			break // EOF, or a partial last line that the next read completes
		}
	}
	if len(hits) > 0 {
		if err := m.storeHits(hits); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.logOff, m.logSize, m.logAt = off, st.Size(), now.Unix()
	m.logLines += int64(lines)
	m.logHits += int64(len(hits))
	m.logUnknown += int64(unknown)
	m.mu.Unlock()
	if lines > 0 {
		_ = m.ctx.Store.Exec(`INSERT OR REPLACE INTO meta VALUES('filterlog_pos', ?)`, fmt.Sprintf("%d %d", off, st.Size()))
	}
	return nil
}

func (m *Module) loadLogPos() (off, size int64) {
	rows, err := m.ctx.Store.Rows(`SELECT value FROM meta WHERE key='filterlog_pos'`)
	if err != nil || len(rows) == 0 {
		return 0, 0
	}
	v, _ := rows[0]["value"].(string)
	fmt.Sscanf(v, "%d %d", &off, &size)
	return off, size
}

// dedupeHits removes the copies an earlier build inserted by replaying the
// log after a restart; a packet is one row.
func (m *Module) dedupeHits() error {
	return m.ctx.Store.Exec(`DELETE FROM policy_hits WHERE id NOT IN (SELECT MIN(id) FROM policy_hits GROUP BY ts,label,src_ip,src_port,dst_ip,dst_port,proto)`)
}

func (m *Module) storeHits(hits []Hit) error {
	return m.ctx.Store.Tx(func(tx *sql.Tx) error {
		ins, err := tx.Prepare(`INSERT INTO policy_hits(ts,policy,label,action,dir,iface,proto,src_ip,src_port,dst_ip,dst_port) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, h := range hits {
			if _, err := ins.Exec(h.TS, h.Policy, h.Label, h.Action, h.Dir, h.Iface, h.Proto, h.SrcIP, h.SrcPort, h.DstIP, h.DstPort); err != nil {
				return err
			}
		}
		return nil
	})
}

func (m *Module) pruneHits() error {
	return m.ctx.Store.Exec(`DELETE FROM policy_hits WHERE ts < ?`, time.Now().Add(-7*24*time.Hour).Unix())
}

// LogStatus is what the hits route reports about the log itself.
func (m *Module) LogStatus() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{"path": m.logPath(), "error": m.logErr, "last_read": m.logAt, "lines_read": m.logLines,
		"hits": m.logHits, "hits_unmapped": m.logUnknown}
}

func (m *Module) apiHits(r *core.Req) (any, error) {
	hours := r.QInt("hours", 24, 1, 24*7)
	limit := r.QInt("limit", 500, 1, 5000)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	q := `SELECT ts,policy,label,action,dir,iface,proto,src_ip,src_port,dst_ip,dst_port FROM policy_hits WHERE ts>=?`
	args := []any{since}
	if pol := r.Q("policy", ""); pol != "" {
		q += ` AND policy=?`
		args = append(args, pol)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, fmt.Errorf("hits: %w", err)
	}
	out := map[string]any{"hits": rows, "log": m.LogStatus(), "since": since}
	if r.Q("debug", "") != "" {
		// The last lines of the log as they are, and the rule numbering the
		// mapping relies on: for when the reader finds nothing and the
		// counters say it should have.
		out["rule_labels"] = m.ruleLabels()
		if b, err := os.ReadFile(m.logPath()); err == nil {
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) > 12 {
				lines = lines[len(lines)-12:]
			}
			for i := range lines {
				if len(lines[i]) > 400 {
					lines[i] = lines[i][:400]
				}
			}
			out["tail"] = lines
			var ours []string
			for _, l := range strings.Split(string(b), "\n") {
				if strings.Contains(l, "flowsight") && len(ours) < 8 {
					ours = append(ours, l)
				}
			}
			out["tail_flowsight"] = ours
		} else {
			out["tail_error"] = err.Error()
		}
	}
	return out, nil
}

// isPolicyAnchor accepts the anchor as filterlog writes it: the leaf name
// on OPNsense, the full path on a pf that logs it that way.
func isPolicyAnchor(a string) bool {
	return a == "policy" || a == rootAnchor+"/policy" || strings.HasSuffix(a, "/policy")
}
