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

// publicAddress is this gateway's own address on the public internet, read
// from its interfaces rather than asked of anyone outside.
func (m *Module) publicAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
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
			if s := ip.String(); !isPrivate(s) {
				return s
			}
		}
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
	for i := range nodes {
		n := &nodes[i]
		if !n.Located || n.RTT <= 0 {
			continue
		}
		km := greatCircleKM(h.Lat, h.Lon, n.Lat, n.Lon)
		floor := floorMS(km)
		n.DistanceKM = math.Round(km)
		n.FloorMS = math.Round(floor*10) / 10
		if n.RTT < floor {
			n.Impossible = true
			n.Why = fmt.Sprintf("answers in %.1f ms, but %.0f km away cannot answer in less than %.0f ms",
				n.RTT, km, floor)
		}
	}
}
