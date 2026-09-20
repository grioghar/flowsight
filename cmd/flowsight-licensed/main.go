// flowsight-licensed is the license server: it keeps activation keys, hands
// out signed license documents to installations that activate with a key,
// refreshes their leases, counts seats and revokes. It also mints offline
// license files for air-gapped installations. One static binary, SQLite,
// the private signing key in a file only this process reads.
//
//	flowsight-licensed serve   -db F -key F -listen :8770 [-admin-token T] [-tls-cert F -tls-key F] [-issuer NAME]
//	flowsight-licensed create  -db F -tier pro|business -licensee NAME [-email E] [-seats N] [-expires YYYY-MM-DD|+365d] [-features a,b] [-limits policies=10] [-note ...]
//	flowsight-licensed list    -db F
//	flowsight-licensed show    -db F -key KEY
//	flowsight-licensed revoke  -db F -key KEY [-reason ...]
//	flowsight-licensed offline -db F -key F -lic KEY [-installation ID]     (prints a signed license file)
//
// HTTP API (JSON):
//
//	POST /v1/activate    {key, installation, hostname, version, platform} -> {token}
//	POST /v1/refresh     same body                                          -> {token}
//	POST /v1/deactivate  {key, installation}                                -> {ok}
//	GET  /v1/health
//	Admin (Authorization: Bearer <admin-token>):
//	POST /admin/licenses            {tier, licensee, email, seats, expires, features, limits, note} -> license
//	GET  /admin/licenses            -> [license]
//	GET  /admin/licenses/{key}      -> license with activations
//	POST /admin/licenses/{key}/revoke   {reason}
//	POST /admin/licenses/{key}/offline  {installation} -> {token}
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/grioghar/flowsight/internal/licensing"
	_ "modernc.org/sqlite"
)

const version = "1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "create":
		err = cmdCreate(args)
	case "list":
		err = cmdList(args)
	case "show":
		err = cmdShow(args)
	case "revoke":
		err = cmdRevoke(args)
	case "offline":
		err = cmdOffline(args)
	case "version", "-version", "--version":
		fmt.Println("flowsight-licensed", version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: flowsight-licensed serve|create|list|show|revoke|offline [flags]  (see -h of each)")
	os.Exit(2)
}

// ---------------------------------------------------------------- storage

type store struct{ db *sql.DB }

type lic struct {
	Key      string         `json:"key"`
	ID       string         `json:"id"`
	Tier     string         `json:"tier"`
	Licensee string         `json:"licensee"`
	Email    string         `json:"email,omitempty"`
	Seats    int            `json:"seats"`
	Issued   string         `json:"issued"`
	Expires  string         `json:"expires,omitempty"`
	Features []string       `json:"features,omitempty"`
	Limits   map[string]int `json:"limits,omitempty"`
	Note     string         `json:"note,omitempty"`
	Revoked  string         `json:"revoked,omitempty"`
	Created  int64          `json:"created"`
}

type activation struct {
	Installation string `json:"installation"`
	Hostname     string `json:"hostname"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	FirstSeen    int64  `json:"first_seen"`
	LastSeen     int64  `json:"last_seen"`
	Released     bool   `json:"released"`
}

func openStore(path string) (*store, error) {
	if path == "" {
		return nil, errors.New("-db is required")
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS licenses (
  key TEXT PRIMARY KEY, id TEXT NOT NULL, tier TEXT NOT NULL, licensee TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
  seats INTEGER NOT NULL DEFAULT 1, issued TEXT NOT NULL, expires TEXT NOT NULL DEFAULT '',
  features TEXT NOT NULL DEFAULT '[]', limits TEXT NOT NULL DEFAULT '{}', note TEXT NOT NULL DEFAULT '',
  revoked TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS activations (
  key TEXT NOT NULL, installation TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
  platform TEXT NOT NULL DEFAULT '', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key, installation));
CREATE TABLE IF NOT EXISTS events (ts INTEGER NOT NULL, key TEXT NOT NULL, installation TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
`)
	if err != nil {
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) insert(l *lic) error {
	f, _ := json.Marshal(l.Features)
	lm, _ := json.Marshal(l.Limits)
	_, err := s.db.Exec(`INSERT INTO licenses (key,id,tier,licensee,email,seats,issued,expires,features,limits,note,revoked,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		l.Key, l.ID, l.Tier, l.Licensee, l.Email, l.Seats, l.Issued, l.Expires, string(f), string(lm), l.Note, l.Revoked, l.Created)
	return err
}

func scanLic(row interface{ Scan(...any) error }) (*lic, error) {
	var l lic
	var f, lm string
	if err := row.Scan(&l.Key, &l.ID, &l.Tier, &l.Licensee, &l.Email, &l.Seats, &l.Issued, &l.Expires, &f, &lm, &l.Note, &l.Revoked, &l.Created); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(f), &l.Features)
	_ = json.Unmarshal([]byte(lm), &l.Limits)
	return &l, nil
}

const licCols = "key,id,tier,licensee,email,seats,issued,expires,features,limits,note,revoked,created"

func (s *store) get(key string) (*lic, error) {
	l, err := scanLic(s.db.QueryRow(`SELECT `+licCols+` FROM licenses WHERE key=?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return l, err
}

func (s *store) list() ([]*lic, error) {
	rows, err := s.db.Query(`SELECT ` + licCols + ` FROM licenses ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*lic
	for rows.Next() {
		l, err := scanLic(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *store) revoke(key, reason string) error {
	if reason == "" {
		reason = "revoked"
	}
	res, err := s.db.Exec(`UPDATE licenses SET revoked=? WHERE key=?`, reason, key)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such key")
	}
	s.event(key, "", "revoke", reason)
	return nil
}

func (s *store) activations(key string) ([]activation, error) {
	rows, err := s.db.Query(`SELECT installation,hostname,version,platform,first_seen,last_seen,released FROM activations WHERE key=? ORDER BY first_seen`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []activation
	for rows.Next() {
		var a activation
		var rel int
		if err := rows.Scan(&a.Installation, &a.Hostname, &a.Version, &a.Platform, &a.FirstSeen, &a.LastSeen, &rel); err != nil {
			return nil, err
		}
		a.Released = rel == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// claim records an activation for an installation, enforcing seats. It
// returns the number of seats in use after the call.
func (s *store) claim(l *lic, installation, hostname, ver, platform string) (int, error) {
	now := time.Now().Unix()
	acts, err := s.activations(l.Key)
	if err != nil {
		return 0, err
	}
	inUse, mine := 0, false
	var names []string
	for _, a := range acts {
		if a.Installation == installation {
			mine = true
			continue
		}
		if !a.Released {
			inUse++
			names = append(names, a.Hostname)
		}
	}
	if !mine && inUse >= l.Seats {
		return inUse, fmt.Errorf("all %d seat(s) of this key are in use (%s); remove the license on one of them first", l.Seats, strings.Join(names, ", "))
	}
	_, err = s.db.Exec(`INSERT INTO activations (key,installation,hostname,version,platform,first_seen,last_seen,released) VALUES (?,?,?,?,?,?,?,0)
		ON CONFLICT(key,installation) DO UPDATE SET hostname=excluded.hostname, version=excluded.version, platform=excluded.platform, last_seen=excluded.last_seen, released=0`,
		l.Key, installation, hostname, ver, platform, now, now)
	if err != nil {
		return 0, err
	}
	if !mine {
		s.event(l.Key, installation, "activate", hostname)
		inUse++
	}
	return inUse, nil
}

func (s *store) release(key, installation string) error {
	_, err := s.db.Exec(`UPDATE activations SET released=1, last_seen=? WHERE key=? AND installation=?`, time.Now().Unix(), key, installation)
	if err == nil {
		s.event(key, installation, "deactivate", "")
	}
	return err
}

func (s *store) event(key, installation, kind, detail string) {
	_, _ = s.db.Exec(`INSERT INTO events (ts,key,installation,kind,detail) VALUES (?,?,?,?,?)`, time.Now().Unix(), key, installation, kind, detail)
}

// ---------------------------------------------------------------- signing

func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key (private signing key file) is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := licensing.ParseKey(string(b), ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return ed25519.PrivateKey(k), nil
}

// token mints a signed document for a license. installation binds it; a
// refresh time marks it as an online lease.
func token(l *lic, priv ed25519.PrivateKey, installation string, refresh time.Duration, issuer string) (string, error) {
	doc := &licensing.License{
		ID: l.ID, Key: last4(l.Key), Tier: l.Tier, Licensee: l.Licensee, Email: l.Email, Seats: l.Seats,
		Issued: l.Issued, Expires: l.Expires, Installation: installation, Issuer: issuer,
		Features: l.Features, Limits: l.Limits, Note: l.Note,
	}
	if refresh > 0 {
		doc.Refresh = time.Now().UTC().Add(refresh).Format(time.RFC3339)
	}
	return licensing.Sign(doc, priv)
}

func last4(k string) string {
	if len(k) < 4 {
		return ""
	}
	return k[len(k)-4:]
}

// ---------------------------------------------------------------- commands

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	db := fs.String("db", "", "database file")
	tier := fs.String("tier", "pro", "pro or business")
	licensee := fs.String("licensee", "", "who the license is for")
	email := fs.String("email", "", "contact e-mail")
	seats := fs.Int("seats", 0, "installations allowed (default: the tier's)")
	expires := fs.String("expires", "+365d", "YYYY-MM-DD, +Nd, or 'never'")
	features := fs.String("features", "", "extra feature keys, comma separated")
	limits := fs.String("limits", "", "limit overrides, e.g. policies=10,retention_days=180")
	note := fs.String("note", "", "free text")
	keyFlag := fs.String("key-text", "", "use this activation key instead of a generated one")
	fs.Parse(args)
	if strings.TrimSpace(*licensee) == "" {
		return errors.New("-licensee is required")
	}
	if !licensing.ValidTier(*tier) || *tier == licensing.TierCommunity {
		return errors.New("-tier must be pro or business")
	}
	exp, err := parseExpiry(*expires)
	if err != nil {
		return err
	}
	l := &lic{Key: *keyFlag, ID: licensing.NewID("lic"), Tier: *tier, Licensee: *licensee, Email: *email, Seats: *seats,
		Issued: time.Now().UTC().Format("2006-01-02"), Expires: exp, Note: *note, Created: time.Now().Unix()}
	if l.Key == "" {
		l.Key = licensing.NewKey(*tier)
	}
	if l.Seats < 1 {
		l.Seats = licensing.Limit(*tier, licensing.LimitInstallations)
	}
	if *features != "" {
		l.Features = splitList(*features)
	}
	if *limits != "" {
		l.Limits = map[string]int{}
		for _, kv := range splitList(*limits) {
			k, v, ok := strings.Cut(kv, "=")
			n, err := strconv.Atoi(v)
			if !ok || err != nil {
				return fmt.Errorf("bad limit %q", kv)
			}
			l.Limits[k] = n
		}
	}
	s, err := openStore(*db)
	if err != nil {
		return err
	}
	if err := s.insert(l); err != nil {
		return err
	}
	s.event(l.Key, "", "create", l.Licensee)
	fmt.Printf("activation key: %s\n  id %s  tier %s  seats %d  expires %s  licensee %s\n", l.Key, l.ID, l.Tier, l.Seats, orNever(l.Expires), l.Licensee)
	return nil
}

func parseExpiry(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch {
	case s == "" || s == "never":
		return "", nil
	case strings.HasPrefix(s, "+") && strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(s, "+"), "d"))
		if err != nil {
			return "", fmt.Errorf("bad expiry %q", s)
		}
		return time.Now().UTC().AddDate(0, 0, n).Format("2006-01-02"), nil
	default:
		if _, err := time.Parse("2006-01-02", s); err != nil {
			return "", fmt.Errorf("bad expiry %q (YYYY-MM-DD, +Nd or never)", s)
		}
		return s, nil
	}
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	db := fs.String("db", "", "database file")
	asJSON := fs.Bool("json", false, "JSON output")
	fs.Parse(args)
	s, err := openStore(*db)
	if err != nil {
		return err
	}
	ls, err := s.list()
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(ls)
	}
	for _, l := range ls {
		acts, _ := s.activations(l.Key)
		used := 0
		for _, a := range acts {
			if !a.Released {
				used++
			}
		}
		state := "active"
		if l.Revoked != "" {
			state = "REVOKED"
		}
		fmt.Printf("%-24s %-9s %-8s seats %d/%d  expires %-10s  %s\n", l.Key, l.Tier, state, used, l.Seats, orNever(l.Expires), l.Licensee)
	}
	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	db := fs.String("db", "", "database file")
	key := fs.String("key", "", "activation key")
	fs.Parse(args)
	s, err := openStore(*db)
	if err != nil {
		return err
	}
	l, err := s.get(licensing.NormalizeKey(*key))
	if err != nil {
		return err
	}
	if l == nil {
		return errors.New("no such key")
	}
	acts, _ := s.activations(l.Key)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"license": l, "activations": acts})
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	db := fs.String("db", "", "database file")
	key := fs.String("key", "", "activation key")
	reason := fs.String("reason", "revoked", "shown to the installation")
	fs.Parse(args)
	s, err := openStore(*db)
	if err != nil {
		return err
	}
	return s.revoke(licensing.NormalizeKey(*key), *reason)
}

func cmdOffline(args []string) error {
	fs := flag.NewFlagSet("offline", flag.ExitOnError)
	db := fs.String("db", "", "database file")
	keyFile := fs.String("key", "", "private signing key file")
	licKey := fs.String("lic", "", "activation key to issue for")
	inst := fs.String("installation", "", "bind to this installation id (optional)")
	issuer := fs.String("issuer", "", "issuer name recorded in the document")
	fs.Parse(args)
	s, err := openStore(*db)
	if err != nil {
		return err
	}
	priv, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	l, err := s.get(licensing.NormalizeKey(*licKey))
	if err != nil {
		return err
	}
	if l == nil {
		return errors.New("no such key")
	}
	if l.Revoked != "" {
		return errors.New("license is revoked")
	}
	tok, err := token(l, priv, *inst, 0, *issuer)
	if err != nil {
		return err
	}
	s.event(l.Key, *inst, "offline", "")
	fmt.Println(tok)
	return nil
}

// ---------------------------------------------------------------- server

type server struct {
	s      *store
	priv   ed25519.PrivateKey
	admin  string
	issuer string
	lease  time.Duration
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	db := fs.String("db", "", "database file")
	keyFile := fs.String("key", "", "private signing key file")
	listen := fs.String("listen", ":8770", "listen address")
	admin := fs.String("admin-token", os.Getenv("FLOWSIGHT_LICENSED_ADMIN_TOKEN"), "bearer token for /admin (empty disables the admin API)")
	issuer := fs.String("issuer", "", "issuer name recorded in documents")
	lease := fs.Duration("lease", 7*24*time.Hour, "how often installations refresh their lease")
	cert := fs.String("tls-cert", "", "TLS certificate (serve plain HTTP behind a proxy when empty)")
	key := fs.String("tls-key", "", "TLS private key")
	fs.Parse(args)
	s, err := openStore(*db)
	if err != nil {
		return err
	}
	priv, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	if *issuer == "" {
		*issuer, _ = os.Hostname()
	}
	sv := &server{s: s, priv: priv, admin: *admin, issuer: *issuer, lease: *lease}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/activate", sv.activate)
	mux.HandleFunc("POST /v1/refresh", sv.activate)
	mux.HandleFunc("POST /v1/deactivate", sv.deactivate)
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": version, "public_key": encodeKey(priv.Public().(ed25519.PublicKey))})
	})
	mux.HandleFunc("/admin/", sv.adminHandler)
	h := &http.Server{Addr: *listen, Handler: logging(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	}()
	log.Printf("flowsight-licensed %s listening on %s (admin API %s, public key %s)", version, *listen, map[bool]string{true: "on", false: "off"}[*admin != ""], encodeKey(priv.Public().(ed25519.PublicKey)))
	if *cert != "" {
		err = h.ListenAndServeTLS(*cert, *key)
	} else {
		err = h.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func encodeKey(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

type activateReq struct {
	Product      string `json:"product"`
	Key          string `json:"key"`
	Installation string `json:"installation"`
	Hostname     string `json:"hostname"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
}

func (sv *server) activate(w http.ResponseWriter, r *http.Request) {
	var in activateReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad", "invalid JSON")
		return
	}
	in.Key = licensing.NormalizeKey(in.Key)
	if in.Key == "" || strings.TrimSpace(in.Installation) == "" {
		writeErr(w, 400, "bad", "key and installation are required")
		return
	}
	l, err := sv.s.get(in.Key)
	if err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	if l == nil {
		writeErr(w, 403, "unknown", "unknown activation key")
		return
	}
	if l.Revoked != "" {
		writeErr(w, 403, "revoked", "this license was revoked: "+l.Revoked)
		return
	}
	if _, err := sv.s.claim(l, in.Installation, in.Hostname, in.Version, in.Platform); err != nil {
		writeErr(w, 409, "seats", err.Error())
		return
	}
	tok, err := token(l, sv.priv, in.Installation, sv.lease, sv.issuer)
	if err != nil {
		writeErr(w, 500, "sign", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok, "tier": l.Tier, "expires": l.Expires})
}

func (sv *server) deactivate(w http.ResponseWriter, r *http.Request) {
	var in activateReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad", "invalid JSON")
		return
	}
	if err := sv.s.release(licensing.NormalizeKey(in.Key), in.Installation); err != nil {
		writeErr(w, 500, "db", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (sv *server) adminHandler(w http.ResponseWriter, r *http.Request) {
	if sv.admin == "" {
		writeErr(w, 404, "off", "admin API disabled")
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(sv.admin)) != 1 {
		writeErr(w, 401, "auth", "admin token required")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/licenses"), "/")
	parts := strings.Split(rest, "/")
	switch {
	case r.Method == "POST" && rest == "":
		var in struct {
			Tier, Licensee, Email, Expires, Note string
			Seats                                int
			Features                             []string
			Limits                               map[string]int
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
			writeErr(w, 400, "bad", "invalid JSON")
			return
		}
		if !licensing.ValidTier(in.Tier) || in.Tier == licensing.TierCommunity || strings.TrimSpace(in.Licensee) == "" {
			writeErr(w, 400, "bad", "tier (pro|business) and licensee are required")
			return
		}
		exp, err := parseExpiry(in.Expires)
		if err != nil {
			writeErr(w, 400, "bad", err.Error())
			return
		}
		l := &lic{Key: licensing.NewKey(in.Tier), ID: licensing.NewID("lic"), Tier: in.Tier, Licensee: in.Licensee, Email: in.Email,
			Seats: in.Seats, Issued: time.Now().UTC().Format("2006-01-02"), Expires: exp, Features: in.Features, Limits: in.Limits,
			Note: in.Note, Created: time.Now().Unix()}
		if l.Seats < 1 {
			l.Seats = licensing.Limit(in.Tier, licensing.LimitInstallations)
		}
		if err := sv.s.insert(l); err != nil {
			writeErr(w, 500, "db", err.Error())
			return
		}
		sv.s.event(l.Key, "", "create", l.Licensee)
		writeJSON(w, 200, l)
	case r.Method == "GET" && rest == "":
		ls, err := sv.s.list()
		if err != nil {
			writeErr(w, 500, "db", err.Error())
			return
		}
		writeJSON(w, 200, ls)
	case r.Method == "GET" && len(parts) == 1:
		l, err := sv.s.get(licensing.NormalizeKey(parts[0]))
		if err != nil || l == nil {
			writeErr(w, 404, "unknown", "no such key")
			return
		}
		acts, _ := sv.s.activations(l.Key)
		writeJSON(w, 200, map[string]any{"license": l, "activations": acts})
	case r.Method == "POST" && len(parts) == 2 && parts[1] == "revoke":
		var in struct{ Reason string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in)
		if err := sv.s.revoke(licensing.NormalizeKey(parts[0]), in.Reason); err != nil {
			writeErr(w, 404, "unknown", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case r.Method == "POST" && len(parts) == 2 && parts[1] == "offline":
		var in struct{ Installation string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in)
		l, err := sv.s.get(licensing.NormalizeKey(parts[0]))
		if err != nil || l == nil {
			writeErr(w, 404, "unknown", "no such key")
			return
		}
		if l.Revoked != "" {
			writeErr(w, 403, "revoked", "license is revoked")
			return
		}
		tok, err := token(l, sv.priv, in.Installation, 0, sv.issuer)
		if err != nil {
			writeErr(w, 500, "sign", err.Error())
			return
		}
		sv.s.event(l.Key, in.Installation, "offline", "")
		writeJSON(w, 200, map[string]any{"token": tok})
	default:
		writeErr(w, 404, "bad", "unknown admin route")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "code": code})
}

func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(t).Round(time.Millisecond))
	})
}
