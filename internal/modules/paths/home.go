package paths

// Where "here" is.
//
// The map needs an origin for two reasons. It is the point every route leaves
// from, and it is the reference for the only check that can falsify a
// placement: light in fibre covers about 200,000 km per second, so a round
// trip cannot beat twice the straight-line distance divided by that, before
// any routing detour or equipment delay is added. A hop that answers faster
// than that floor is not in the place the database says it is.
//
// Left alone, "here" is worked out from the gateway's own public address. That
// is usually the right town and occasionally the wrong state, because it is
// where the carrier registered the block rather than where the wire ends. So
// it can be declared instead, and the page offers two ways to fill it in: ask
// the browser, which knows precisely and asks permission, or take the
// database's answer for the public address.

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

// earthKM is the mean radius; fibreKMS is light in glass, about two thirds of
// its speed in vacuum.
const (
	earthKM  = 6371.0
	fibreKMS = 200000.0
)

// Home is the origin the map is drawn from.
type Home struct {
	Lat, Lon float64
	Source   string // "declared" or "public address"
	OK       bool
}

// home returns the origin: what was declared, or failing that the database's
// answer for this gateway's own public address.
func (m *Module) home() Home {
	if lat, lon, ok := parseLatLon(core.Str(m.ctx.Settings(), "home", "")); ok {
		return Home{Lat: lat, Lon: lon, Source: "declared", OK: true}
	}
	if ip := m.publicAddress(); ip != "" && m.rdns != nil {
		if info, found := m.rdns.Lookup([]string{ip})[ip]; found && (info.Lat != 0 || info.Lon != 0) {
			return Home{Lat: info.Lat, Lon: info.Lon, Source: "public address", OK: true}
		}
	}
	return Home{}
}

// publicAddresses are this gateway's own addresses on the public internet,
// read from its interfaces rather than asked of anyone outside. IPv4 first,
// then IPv6, each sorted, so the answer is the same every time it is asked.
//
// "Not private" is not enough to find them. A delegated IPv6 prefix is
// globally routable and still belongs to this network, so the LAN address
// matches every test for a public one. Identity knows which prefixes are
// ours, and that is the only thing that can tell them apart.
func (m *Module) publicAddresses() (v4, v6 []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip == nil {
				continue
			}
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				continue
			}
			s := ip.String()
			if isPrivate(s) {
				continue
			}
			if m.identity != nil && m.identity.IsLocal(s) {
				continue // routable, but on this side of the firewall
			}
			if ip.To4() != nil {
				if !contains(v4, s) {
					v4 = append(v4, s)
				}
			} else if !contains(v6, s) {
				v6 = append(v6, s)
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// publicAddress is the one address the origin is worked out from.
//
// IPv4 by preference, and not as a matter of taste: the interface walk has no
// defined order, so taking whichever address turned up first meant a
// dual-stack gateway could locate itself from v6 on one run and v4 on the
// next. The origin is what decides whether a hop could be where the database
// claims, so an origin that moves between restarts quietly moves the line
// between a placement that is ruled out and one that stands. IPv4 also
// geolocates better, v6 blocks being newer and more coarsely registered.
func (m *Module) publicAddress() string {
	v4, v6 := m.publicAddresses()
	if len(v4) > 0 {
		return v4[0]
	}
	if len(v6) > 0 {
		return v6[0]
	}
	return ""
}

func parseLatLon(s string) (float64, float64, bool) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ",")
	if !ok {
		return 0, 0, false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(a), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, false
	}
	if lat == 0 && lon == 0 {
		return 0, 0, false // the point in the Gulf of Guinea that means "unset"
	}
	return lat, lon, true
}

// greatCircleKM is the straight-line distance over the earth's surface.
func greatCircleKM(lat1, lon1, lat2, lon2 float64) float64 {
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp, dl := (lat2-lat1)*math.Pi/180, (lon2-lon1)*math.Pi/180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return earthKM * 2 * math.Asin(math.Sqrt(a))
}

// floorMS is the fastest a round trip to a point could possibly be: straight
// there and straight back through glass, with nothing in between.
func floorMS(km float64) float64 { return 2 * km / fibreKMS * 1000 }

// checkPlausible marks the placements the measured latency rules out. It never
// moves a point or invents one; it says which ones cannot be where they claim.

func (m *Module) checkPlausible(nodes []Node, h Home) {
	if !h.OK {
		return
	}
	hop := m.hopDelayMS()
	for i := range nodes {
		n := &nodes[i]
		if !n.Located || n.RTT <= 0 {
			continue
		}
		// Two numbers, answering two different questions.
		//
		// The floor is what light forbids, measured along the cables where a
		// crossing has to follow one. It is a proof, and it is rigorous
		// because it assumes a perfect path: dead straight, nothing attached.
		//
		// The expectation is what a route that exists could manage: fibre on
		// land runs about a third longer than the crow flies, a sea crossing
		// is as long as its cable, and every router on the way holds the
		// packet for a moment before passing it on. A hop under this is not
		// disproved -- it is beating anything anyone has built, which is a
		// different and softer claim, and the two must not be run together.
		km, via := m.pathKM(h.Lat, h.Lon, n.Lat, n.Lon)
		floor := floorMS(km)
		n.DistanceKM = math.Round(km)
		n.FloorMS = math.Round(floor*10) / 10
		n.Via = via

		ekm, evia := m.expectedKM(h.Lat, h.Lon, n.Lat, n.Lon)
		if ekm < km {
			ekm = km // an expectation below the bound is not an expectation
		}
		expected := floorMS(ekm) + hop*float64(n.Index)
		n.ExpectedKM = math.Round(ekm)
		n.ExpectedMS = math.Round(expected*10) / 10
		n.ExpectedVia = evia

		switch {
		case n.RTT < floor:
			n.Impossible = true
			n.Why = fmt.Sprintf("answers in %.1f ms, but %.0f km away%s cannot answer in less than %.0f ms",
				n.RTT, km, viaPhrase(via), floor)
		case expected > floor && n.RTT < expected:
			n.Tight = true
			n.Why = fmt.Sprintf("answers in %.1f ms, which light allows over %.0f km%s but no built route does: %s comes to %.0f ms, and %d hop%s add %.1f ms more",
				n.RTT, km, viaPhrase(via), expectedPhrase(ekm, evia), floorMS(ekm), n.Index, plural(n.Index), hop*float64(n.Index))
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// expectedPhrase says where the realistic distance came from, because a
// number a reader cannot trace is one they have to take on trust.
func expectedPhrase(km float64, via string) string {
	if via != "" {
		return fmt.Sprintf("%.0f km along %s", km, via)
	}
	return fmt.Sprintf("%.0f km once fibre's detours are allowed for", km)
}

// viaPhrase names the cable a distance was measured along, when one was.
func viaPhrase(via string) string {
	if via == "" {
		return ""
	}
	return " by the shortest cable route (" + via + ")"
}
