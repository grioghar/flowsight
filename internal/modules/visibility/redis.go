package visibility

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// A minimal RESP client: enough to read and write the handful of keys ntopng
// keeps its users in. No dependency, no cgo, and it lets Flowsight provision
// its own ntopng account instead of asking the operator to click through
// ntopng's password-change screen.
type redis struct {
	addr string
	conn net.Conn
	rd   *bufio.Reader
}

func dialRedis(addr string) (*redis, error) {
	network := "tcp"
	if strings.HasPrefix(addr, "/") {
		network = "unix"
	}
	c, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &redis{addr: addr, conn: c, rd: bufio.NewReader(c)}, nil
}

func (r *redis) close() { _ = r.conn.Close() }

func (r *redis) do(args ...string) (any, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := r.conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return r.read()
}

func (r *redis) read() (any, error) {
	line, err := r.rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("redis: empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, errors.New("redis: " + line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, _ := strconv.Atoi(line[1:])
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := ioReadFull(r.rd, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, _ := strconv.Atoi(line[1:])
		if n < 0 {
			return nil, nil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := r.read()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, errors.New("redis: unexpected reply " + line)
}

func ioReadFull(rd *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := rd.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (r *redis) get(key string) (string, bool, error) {
	v, err := r.do("GET", key)
	if err != nil || v == nil {
		return "", false, err
	}
	s, _ := v.(string)
	return s, true, nil
}

// provisionNtopngUser creates (or resets) an ntopng account the way ntopng's
// own Lua does: a handful of plain keys with an MD5 password hash. Returns
// the password. ntopng reads these on every login, so no restart is needed.
func provisionNtopngUser(addr, user string) (string, error) {
	r, err := dialRedis(addr)
	if err != nil {
		return "", fmt.Errorf("redis %s: %w", addr, err)
	}
	defer r.close()
	if _, err := r.do("PING"); err != nil {
		return "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	password := hex.EncodeToString(raw)
	sum := md5.Sum([]byte(password))
	prefix := "ntopng.user." + user + "."
	sets := map[string]string{
		prefix + "password":         hex.EncodeToString(sum[:]),
		prefix + "group":            "administrator",
		prefix + "full_name":        "Flowsight",
		prefix + "allowed_nets":     "0.0.0.0/0,::/0",
		prefix + "allowed_ifname":   "",
		prefix + "language":         "en",
		prefix + "allow_pcap":       "false",
		prefix + "allow_historical": "false",
	}
	for k, v := range sets {
		if _, err := r.do("SET", k, v); err != nil {
			return "", err
		}
	}
	return password, nil
}

// ntopngUserExists reports whether a password key is present.
func ntopngUserExists(addr, user string) bool {
	r, err := dialRedis(addr)
	if err != nil {
		return false
	}
	defer r.close()
	_, ok, _ := r.get("ntopng.user." + user + ".password")
	return ok
}
