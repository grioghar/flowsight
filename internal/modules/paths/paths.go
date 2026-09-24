// Package paths answers a question the rest of FlowSight cannot: not what
// left the network, but which way it went.
//
// Everything else here watches the first hop. A flow record says a device
// reached an address; it says nothing about the fifteen routers in between,
// whose country, carrier and latency decide whether a connection is fast,
// legal, and going where you think it is.
//
// So this traces the destinations the network actually talks to, drawn from
// the history rather than probed at large, and keeps what it finds. A path
// belongs to a destination, not to a device: everything leaves through the
// same gateway, so the route from here to a given address is the same
// whichever device asked for it. A device is linked to a path because it has
// flows to that destination, which is a join rather than another trace.
//
// What this is not: a map of where packets physically are. Intermediate
// routers geolocate badly, often to wherever their address block was
// registered, and a single trace is one sample of a path that varies per
// flow. Every hop carries where its location came from, so a reader can tell
// a measured answer from a registrar's guess.
package paths

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/enrich"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module implements core.Module.
type Module struct {
	ctx      *core.Context
	run      tracer
	rdns     lookup
	identity core.Identity

	mu             sync.Mutex
	lastRun        time.Time
	traced         int
	lastErr        string
	cables         []Cable
	nets           []cableNet // the same cables stitched back into connected systems
	landNets       []cableNet // mapped terrestrial routes, where anyone publishes them
	landRoutes     int
	landErr        string
	osmNets        []cableNet // OpenStreetMap telecom lines, at half weight
	osm            osmState
	osmUntil       time.Time      // do not ask Overpass again before this
	hopBoxes       map[string]int // placed hops per OSM region, from the last graph
	providers      *providerIndex // the clouds' published ranges
	provider       providerState
	abuseErr       string
	shodanAsked    int
	fcc            fccState
	fccSum         *fccSummary
	fccPullRunning bool // prevent concurrent fccPull runs
	censusErr      string
	shodanErr      string
	assistQueue    []assistCandidate
	assistAsked    []time.Time
	assistTotal    int
	assistErr      string
	nsidQueue      []assistCandidate
	nsidAsked      int
	nsidPlaced     int
	rootSites      []rootSite
	rootByID       map[string]rootSite
	abuseAsked     int
	cableErr       string
	pending        map[string]bool // addresses still needing the slow registry lookup
	geoPending     map[string]bool // addresses still to be asked about at IPmap
	ipmapUntil     time.Time       // do not ask IPmap again before this
	ipmapAnswered  int             // answers kept this session, for the status page
	graphCache     map[string]cachedGraph
	routes         routeMemo     // cable and land-route searches, answered once per pair of places
	cands          candidateMemo // cables passing near both ends of a leg, likewise
	graphBuild     sync.Mutex    // one graph build at a time; the rest wait and reuse it
	fixes          fixes         // what the database gets wrong, learned from names and measurements
}

// lookup is the part of the enrich module this needs.
type lookup interface {
	Lookup(ips []string) map[string]enrich.Info
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "paths",
		Version:     "1.0",
		Tier:        "pro",
		Description: "The route to the places this network talks to: every hop with its name, carrier and location, collapsed where paths share a leg.",
		After:       []string{"enrich", "visibility", "web"},
		Defaults: map[string]any{
			"enabled":                true,
			"active":                 false,
			"per_run":                6,
			"retrace_hours":          24,
			"max_destinations":       300,
			"trace_ipv6":             true,
			"home":                   "",
			"cables":                 false,
			"cables_url":             "",
			"cable_near_km":          400,
			"registry":               true,
			"ipmap":                  true,
			"ipmap_per_minute":       20,
			"land_detour_pct":        35,
			"origin_slack_km":        100,
			"hop_delay_us":           200,
			"terrestrial":            false,
			"learn_corrections":      true,
			"terrestrial_urls":       "",
			"osm_telecom":            true,
			"provider_feeds":         true,
			"anycast_census":         true,
			"shodan_key":             "",
			"shodan_mode":            "click",
			"fcc_username":           "",
			"fcc_token":              "",
			"identify":               true,
			"geofeeds":               true,
			"abuseipdb_key":          "",
			"ai_provider":            "off",
			"ai_endpoint":            "",
			"ai_model":               "",
			"ai_key":                 "",
			"ai_per_hour":            20,
			"azure_service_tags_url": "",
			"osm_overpass_url":       "",
			"osm_overpass_local":     false,
			"facilities":             true,
		},
		Schema: []core.SettingField{
			{Section: "Tracing", Key: "active", Label: "Trace paths", Type: "bool",
				Help: "Off: nothing is traced. On: FlowSight runs a traceroute to a few of the destinations this network has actually contacted, on a timer, and keeps the route it finds. It never probes anything the network has not already talked to."},
			{Section: "Tracing", Key: "per_run", Label: "Destinations traced per run", Type: "int",
				Help: "A traceroute takes seconds and the runs are spread out, so this is deliberately small. Raising it finds new paths sooner and costs more outbound probes."},
			{Section: "Tracing", Key: "retrace_hours", Label: "Trace a destination again after (hours)", Type: "int",
				Help: "Paths change. This decides how stale a route is allowed to get before it is measured again."},
			{Section: "Tracing", Key: "max_destinations", Label: "Destinations kept", Type: "int",
				Help: "The busiest destinations are traced first; beyond this the long tail is left alone."},
			{Section: "Tracing", Key: "trace_ipv6", Label: "Trace IPv6 destinations too", Type: "bool"},
			{Section: "Where things are", Key: "cables", Label: "Show submarine cables", Type: "bool",
				Help: "Downloads TeleGeography's public cable map (about a megabyte, refreshed monthly) and draws it behind the routes. A traceroute never names a cable, so no leg is claimed to follow one; what this gives is the cables that could have carried a leg, minus the ones too long to have produced the latency measured."},
			{Section: "Where things are", Key: "cable_near_km", Label: "A cable serves a place within (km)", Type: "int",
				Help: "How close a cable has to pass to count. Landfalls are rarely where a router is, and a router is rarely exactly where the database says, so this is deliberately loose."},
			{Section: "What the latency proves", Key: "origin_slack_km", Label: "Your own position could be wrong by (km)", Type: "int",
				Help: "Every distance on the map is measured from your origin, and unless you declared it that origin came from the address database, which is routinely tens of kilometres out. A placement is only called impossible if it misses its floor by more than this, because calling one impossible on a thinner margin claims a precision the origin does not have. It only ever withdraws accusations. A declared origin gets no allowance."},
			{Section: "What the latency proves", Key: "land_detour_pct", Label: "Fibre on land runs longer than the crow flies by (%)", Type: "int",
				Help: "Cable does not go straight overland: it follows roads, railways and rights of way, and detours around whatever could not be dug through. This is how much longer, and it decides the second of the two numbers each hop is judged against -- not what light forbids, which is a separate and harder bound, but what a route that actually exists could manage. A hop faster than that is doing better than anything anyone has built. Zero turns the category off."},
			{Section: "What the latency proves", Key: "hop_delay_us", Label: "Each hop adds (microseconds)", Type: "int",
				Help: "A router has to finish receiving a packet before it can start sending it on, and that time is spent at every hop. Small individually; over twenty hops it is worth counting."},
			{Section: "Where things are", Key: "terrestrial", Label: "Use published land-route maps", Type: "bool",
				Help: "Downloads open maps of long-haul fibre on land and measures along them where they reach, instead of estimating the detour. These never raise the impossible threshold: over water a cable is the only way across, so its length is a real bound, but on land a straight line is merely something nobody built. Coverage is thin -- AfTerFibre covers Africa under a Creative Commons licence and is the one substantial open set; the comprehensive maps of North America, Europe and Asia are sold commercially. Refreshed monthly."},
			{Section: "Where things are", Key: "terrestrial_urls", Label: "Land-route sources", Type: "text",
				Help: "One GeoJSON URL per line, replacing the defaults. Lines starting with # or // are ignored, so a source can be kept and turned off."},
			{Section: "AI lookup", Key: "ai_provider", Label: "Ask a language model about hops nothing else can place", Type: "choice",
				Choices: []string{"off", "anthropic", "openai", "google", "azure", "ollama", "custom"},
				Help:    "Only hops that answered and that no name, provider feed, geofeed, measurement or database could place are put to the model: the hostname, the network and operator, and the round trip from here. Its answer is a hypothesis -- checked against the clock like a router name, drawn as an inference, marked as the model's reading on the card -- and never overrules a source that knows. Setting up: ANTHROPIC -- console.anthropic.com › API Keys › Create Key; default model claude-haiku-4-5. OPENAI -- platform.openai.com › API keys; default gpt-4o-mini. GOOGLE -- aistudio.google.com › Get API key; default gemini-2.0-flash. AZURE -- in Azure OpenAI Studio deploy a chat model, then paste the deployment's chat/completions URL (https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-10-21) as the endpoint and a key from Keys and Endpoint. OLLAMA -- run ollama locally, pull a model (ollama pull llama3.1), leave the endpoint empty for http://127.0.0.1:11434 or set your host's; no key. CUSTOM -- any OpenAI-compatible chat/completions endpoint and, if it needs one, a key. Hostnames are sent to whichever service you choose."},
			{Section: "AI lookup", Key: "ai_endpoint", Label: "Endpoint", Type: "string", Placeholder: "leave empty for the provider's default",
				Help: "Required for Azure (the deployment URL) and custom; optional otherwise. Google's may contain {model}."},
			{Section: "AI lookup", Key: "ai_model", Label: "Model", Type: "string", Placeholder: "provider default",
				Help: "Any chat model the provider offers. Small, fast models are plenty for this."},
			{Section: "AI lookup", Key: "ai_key", Label: "API key", Type: "secret",
				Help: "Sent only to the endpoint above. Not needed for Ollama."},
			{Section: "AI lookup", Key: "ai_per_hour", Label: "Questions per hour", Type: "int",
				Help: "Each hop is asked about once a month at most; this caps how many new ones per hour. Twenty is a few cents a day on the small models."},
			{Section: "FCC broadband map", Key: "fcc_username", Label: "FCC broadband map username", Type: "string",
				Help: "The National Broadband Map's data API needs an account. Create one free at broadbandmap.fcc.gov (Login › Create account), then under your account find the API token. Enter the account's username here and the token below; FlowSight then checks in monthly for the current release and its files, and keeps the state-level provider summaries. Without both fields nothing is asked."},
			{Section: "FCC broadband map", Key: "fcc_token", Label: "FCC API token", Type: "secret",
				Help: "Sent only in the hash_value header of requests to broadbandmap.fcc.gov. Press Check FCC access on the Map page’s Data sources card after entering it."},
			{Section: "Shodan", Key: "shodan_key", Label: "Shodan API key", Type: "secret",
				Help: "Optional. Without a key FlowSight uses Shodan's free InternetDB (open ports, hostnames, product fingerprints, known vulnerabilities) and asks nothing else. With a key the full host record is added -- organisation, ISP, operating system, Shodan's own location, last seen -- at one query credit per address. To get a key: sign in at account.shodan.io and copy the API key shown at the top; the free tier includes 100 query credits a month, so the keyed record is fetched on click unless you choose it for every hop below. The key is sent only to api.shodan.io."},
			{Section: "Shodan", Key: "shodan_mode", Label: "Look hops up on Shodan", Type: "choice", Choices: []string{"off", "click", "all"},
				Help: "off: never. click: when you press Look up on Shodan on a hop's card (the InternetDB part is free; the keyed part costs a credit). all: every hop on a route, twenty every five minutes -- InternetDB always, and the keyed record too if a key is set, which will spend credits."},
			{Section: "Reputation", Key: "abuseipdb_key", Label: "AbuseIPDB API key", Type: "secret",
				Help: "With a key, every hop on a route is checked against AbuseIPDB -- abuse confidence, reports, ISP, usage type -- and the answer shown on its card and kept a week. Twenty addresses are asked about every few minutes, well inside the free allowance of a thousand a day. To get a key: create a free account at abuseipdb.com, open Account \u203a API, click Create Key, and paste it here. Leave empty to disable."},
			{Section: "Where things are", Key: "geofeeds", Label: "Follow geofeeds named in the registry", Type: "bool",
				Help: "Some operators publish where their prefixes are (RFC 8805, prefix, country, region, city) and name the file in their registry object. FlowSight already asks the registry about every hop; with this on it keeps any geofeed it is pointed to, fetches each once a week, and uses its rows like a provider's own range list. Listed at /api/paths/geofeeds."},
			{Section: "Where things are", Key: "anycast_census", Label: "Know which addresses are anycast", Type: "bool",
				Help: "The LACeS anycast census (University of Twente and CAIDA) publishes daily the prefixes it detects as anycast -- forty thousand IPv4, eighteen thousand IPv6 -- with the sites each is served from. Fetched weekly. For a hop in one of them the map says so: announced from many datacentres at once, and from here you are reaching a local or regional instance, the site nearest the hop before it. A registered or measured position for such an address is set aside. Addresses of known anycast operators (Google, Cloudflare, Akamai, Apple, Amazon, Microsoft, Meta, the DNS providers) are treated the same when nothing authoritative places them."},
			{Section: "Where things are", Key: "identify", Label: "Ask anycast servers to identify themselves", Type: "bool",
				Help: "Root servers and large resolvers answer a CHAOS TXT query for id.server with the name of the instance that answered -- DFW.cf.f.root-servers.org, c01.MCI.eroot. The root operators publish their site lists with those identifiers, fetched weekly, so an answer is looked up rather than guessed; elsewhere the airport code in it is read like a router name. The clock still rules. One small packet per server, twenty per run, remembered a week."},
			{Section: "Where things are", Key: "provider_feeds", Label: "Use the clouds' published address ranges", Type: "bool",
				Help: "AWS, Google Cloud, Microsoft Azure, Oracle Cloud, DigitalOcean and Linode publish which prefixes they use in which region; Cloudflare and Fastly publish their anycast ranges. For an address in one of those ranges this is the operator's own statement of where it is and outranks the address database and a latency estimate. An anycast address is announced everywhere at once, so a database position for one is set aside and the hop is placed by timing. Fetched weekly; Microsoft's file is read as a stream and kept compact."},
			{Section: "Where things are", Key: "azure_service_tags_url", Label: "Azure service tags file", Type: "string",
				Help: "Empty: found on Microsoft's download page each week. Set it only if that discovery fails."},
			{Section: "Where things are", Key: "osm_telecom", Label: "Use OpenStreetMap telecom lines (low weight)", Type: "bool",
				Help: "Fibre and telecom lines where OpenStreetMap mappers have drawn them: dense in a few well-mapped countries, absent elsewhere, and mostly the visible kind. Used at half weight -- where a line offers a route between two hops, the expected time is the average of following it and the plain detour estimate. Never touches the physics floor; never drawn as the route. Fetched from the Overpass API one ten-degree tile per run, twenty minutes apart while any are outstanding, kept a month, starting with the tiles your traffic crosses; a timeout waits an hour, a refusal six."},
			{Section: "Where things are", Key: "osm_overpass_url", Label: "Overpass API", Type: "string",
				Help: "Empty: overpass-api.de. Point it at your own Overpass instance if you run one; the public service is shared and asked gently."},
			{Section: "Where things are", Key: "osm_overpass_local", Label: "My Overpass is on this network", Type: "bool",
				Help: "Every URL FlowSight fetches is normally required to be a public host, so the daemon cannot be turned into a way into the network it protects. A private Overpass -- one you run in a container beside the gateway -- is the exception; turn this on to allow the Overpass API above to be a private address. Nothing else is exempted."},
			{Section: "Where things are", Key: "learn_corrections", Label: "Remember what the database gets wrong", Type: "bool",
				Help: "When a router's own name or a RIPE measurement places a hop far from where the address database put it, the hop's announced prefix is remembered as being where the evidence says, and other addresses in that prefix follow it. A registrant address the database uses for a whole network -- a carrier's head office stamped on every block -- is set aside once two of its addresses are shown to be elsewhere; hops the database would put there are placed by timing instead. Listed at /api/paths/corrections; any item can be forgotten."},
			{Section: "Where things are", Key: "ipmap", Label: "Ask RIPE where each router is", Type: "bool",
				Help: "RIPE's IPmap publishes where addresses are, worked out by measuring them from thousands of probes and narrowing by latency \u2014 the same argument FlowSight makes about impossibility, run at scale. It is the one source here that is measurement rather than paperwork, and it outranks the address database. Asked slowly and remembered for a month; a refusal backs off for half an hour."},
			{Section: "Where things are", Key: "ipmap_per_minute", Label: "Addresses asked about per minute", Type: "int",
				Help: "Deliberately small. There is no hurry \u2014 answers last a month and routers do not move \u2014 and the service belongs to somebody else."},
			{Section: "Where things are", Key: "registry", Label: "Look up who runs each hop", Type: "bool",
				Help: "Asks the public routing table which network announces a hop's address, and the regional registry who that block is allocated to. The registry's postal address is a head office, not the room the router is in, and is labelled that way. Results are kept for a month, because none of it changes quickly."},
			{Section: "Where things are", Key: "facilities", Label: "List buildings the operator occupies", Type: "bool",
				Help: "Adds street addresses from PeeringDB, where operators publish which data centres they are in. This is only narrowed to a hop when the router's own name gave away its city; otherwise it is every building that operator occupies anywhere, and is shown as such rather than as an answer."},
			{Section: "Where things are", Key: "cables_url", Label: "Cable map URL", Type: "string",
				Help: "Empty: TeleGeography's published map. Their data is a free public resource but is not openly licensed, so it is fetched by each installation rather than shipped with FlowSight."},
			{Section: "Where things are", Key: "home", Label: "Your location", Type: "string", Placeholder: "39.1836,-96.5717",
				Help: "Latitude and longitude, comma separated. The map is drawn from here, and it is the reference for checking whether a hop could really be where the database says: nothing can answer faster than light in fibre takes to get there and back. Empty: worked out from this gateway's public address, which is usually the right town and sometimes the wrong state. The Map page can fill it in from your browser, which knows precisely."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.fixes.load(ctx.Store)
	m.providers = &providerIndex{v4: map[byte][]providerRange{}, v6: map[uint16][]providerRange{}}
	addKnownAnycast(m.providers)
	// Whatever is already on disk -- provider ranges, geofeeds, the anycast
	// census -- is loaded at start rather than at the first scheduled run
	// half an hour later; off the main path, since the census is large.
	go func() { _ = m.loadProviders(map[string]providerStats{}) }()
	m.fixes.on = core.Bool(ctx.Settings(), "learn_corrections", true)
	if m.run == nil {
		m.run = runTraceroute
	}
	m.rdns, _ = ctx.Service("enrich").(lookup)
	m.identity, _ = ctx.Service("identity").(core.Identity)
	if err := m.migrate(); err != nil {
		return err
	}
	ctx.Every("trace", 5*time.Minute, m.sweep)
	ctx.Every("cables", 12*time.Hour, m.refreshCables)
	// Detail is gathered away from anyone waiting for a page. See warm().
	ctx.Every("detail", 45*time.Second, m.warm)
	// Long-haul routes change over years and these datasets are revised
	// rarely, so the job wakes often and downloads almost never.
	ctx.Every("terrestrial", 12*time.Hour, m.refreshTerrestrial)
	ctx.Every("osm", 20*time.Minute, m.refreshOSM, core.Delayed())
	ctx.Every("providers", 30*time.Minute, m.refreshProviders, core.Delayed())
	ctx.Every("geofeeds", 30*time.Minute, m.refreshGeofeeds, core.Delayed())
	ctx.Every("reputation", 5*time.Minute, m.reputationJob, core.Delayed())
	ctx.Every("assistant", 5*time.Minute, m.assistantJob, core.Delayed())
	ctx.Every("identify", 5*time.Minute, m.identifyJob, core.Delayed())
	ctx.Every("rootsites", 24*time.Hour, m.refreshRootSites, core.Delayed())
	ctx.Every("census", 24*time.Hour, m.refreshCensus, core.Delayed())
	ctx.Every("shodan", 5*time.Minute, m.shodanJob, core.Delayed())
	ctx.Every("fcc", 24*time.Hour, m.fccJob, core.Delayed())
	ctx.Every("fccpull", 24*time.Hour, m.fccPull, core.Delayed())
	_ = m.loadFCCSummary()
	_ = m.loadRootSites()
	// Asking where routers really are, slowly and forever. See ipmap.go.
	ctx.Every("locate", time.Minute, m.locateBatch)
	ctx.Route("GET", "/api/paths/fcc/files", m.apiFCCFiles, core.Needs("paths.map"),
		core.Doc("The FCC release's file catalogue from the last check"), core.Params("filter", "substring", "limit", "rows"))
	ctx.Route("GET", "/api/paths/fcc/summary", m.apiFCCSummary, core.Needs("paths.map"),
		core.Doc("What was kept from the FCC release: national fixed-broadband providers and the origin state's census places"), core.Params("full", "1 for every provider"))
	ctx.Route("POST", "/api/paths/fcc/pull", m.apiFCCPull, core.Write(), core.Needs("paths.map"),
		core.Doc("Run the monthly FCC pull now"))
	ctx.Route("POST", "/api/paths/fcc/check", m.apiFCCCheck, core.Write(), core.Needs("paths.map"),
		core.Doc("Test the FCC broadband map credentials and record the current release"))
	ctx.Route("GET", "/api/paths/shodan", m.apiShodan, core.Needs("paths.map"),
		core.Doc("Shodan record for a hop: InternetDB always, the keyed host record when a key is set; fetched now with now=1"),
		core.Params("ip", "the address", "now", "1 to fetch if not cached"))
	ctx.Route("GET", "/api/paths/geofeeds", m.apiGeofeeds, core.Needs("paths.map"),
		core.Doc("RFC 8805 geofeeds discovered in registry objects, with fetch state"))
	ctx.Route("GET", "/api/paths/talkers", m.apiTalkers, core.Needs("paths.map"),
		core.Doc("Which devices talked to an endpoint and over which services (application, name, port)"),
		core.Params("dst", "the endpoint", "hours", "window, default 24"))
	ctx.Route("GET", "/api/paths/corrections", m.apiCorrections, core.Needs("paths.map"),
		core.Doc("What the address database has been shown to get wrong: corrected prefixes and distrusted registrant coordinates"))
	ctx.Route("POST", "/api/paths/corrections/forget", m.apiForgetFix, core.Write(), core.Needs("paths.map"),
		core.Doc("Forget one learned correction (prefix) or distrusted coordinate (key)"))
	ctx.Route("GET", "/api/paths/status", m.apiStatus, core.Needs("paths.map"),
		core.Doc("Whether tracing is on, how many destinations have a route, and when"))
	ctx.Route("GET", "/api/paths/destinations", m.apiDestinations, core.Needs("paths.map"),
		core.Doc("Destinations with a measured route"), core.Params("limit", "rows"))
	ctx.Route("GET", "/api/paths/path", m.apiPath, core.Needs("paths.map"),
		core.Doc("Every hop to one destination, with names and locations"), core.Params("dst", "destination"))
	ctx.Route("GET", "/api/paths/devices", m.apiDevices, core.Needs("paths.map"),
		core.Doc("Devices whose traffic has a measured route, one entry per device"))
	ctx.Route("GET", "/api/paths/graph", m.apiGraph, core.Needs("paths.map"),
		core.Doc("The whole picture as nodes and legs, with shared legs collapsed"),
		core.Params("device", "source address", "country", "filter", "max_latency", "ms"))
	ctx.Route("GET", "/api/paths/cables", m.apiCables, core.Needs("paths.map"),
		core.Doc("The submarine cable map, simplified for drawing"), core.Params("detail", "points per cable"))
	ctx.Route("GET", "/api/paths/home", m.apiGetHome, core.Needs("paths.map"),
		core.Doc("The origin the map is drawn from, and what could be detected for it"))
	ctx.Route("POST", "/api/paths/home", m.apiSetHome, core.Write(), core.Needs("paths.map"),
		core.Doc("Declare your location ({lat, lon}), or {clear:true} to go back to detecting it"))
	ctx.Panel(core.Panel{ID: "paths", Title: "Map", Group: "Visibility", Order: 50, Icon: "paths", Feature: "paths.map"})
	return nil
}

func (m *Module) migrate() error {
	return m.ctx.Store.Exec(`
CREATE TABLE IF NOT EXISTS path_hops (
    dst TEXT NOT NULL,
    idx INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    rtt_ms REAL,
    first_seen INTEGER, last_seen INTEGER,
    PRIMARY KEY (dst, idx, ip)
);
CREATE INDEX IF NOT EXISTS path_hops_ip ON path_hops(ip);
CREATE TABLE IF NOT EXISTS path_runs (
    dst TEXT PRIMARY KEY,
    ts INTEGER, hops INTEGER, complete INTEGER, err TEXT
);`)
}

func (m *Module) Health() core.Health {
	if !core.Bool(m.ctx.Settings(), "active", false) {
		return core.Health{OK: true, Detail: "off; nothing is traced"}
	}
	if err := m.ctx.License().Allowed("paths.map"); err != nil {
		return core.Health{OK: true, Detail: "needs the pro tier"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.lastRun.IsZero() {
		return core.Health{OK: true, Detail: "waiting for the first run"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d destinations traced, last run %s ago",
		m.traced, time.Since(m.lastRun).Round(time.Second))}
}

// ---------------------------------------------------------------- tracing

// sweep traces a few destinations that have no recent route.
func (m *Module) sweep() error {
	if !core.Bool(m.ctx.Settings(), "active", false) {
		return nil
	}
	if err := m.ctx.License().Allowed("paths.map"); err != nil {
		return nil
	}
	targets, err := m.due()
	if err != nil {
		m.fail(err.Error())
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	n := 0
	for _, dst := range targets {
		if ctx.Err() != nil {
			break
		}
		t := m.trace(ctx, dst, strings.Contains(dst, ":"))
		if err := m.save(t); err != nil {
			m.fail(err.Error())
			return nil
		}
		n++
	}
	m.mu.Lock()
	m.lastRun, m.lastErr = time.Now(), ""
	m.traced += n
	m.mu.Unlock()
	return nil
}

func (m *Module) fail(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

// due picks the destinations worth tracing: the ones this network talks to
// most, that have no route or whose route has gone stale.
func (m *Module) due() ([]string, error) {
	s := m.ctx.Settings()
	per := core.Int(s, "per_run", 6)
	if per < 1 {
		per = 1
	}
	stale := time.Now().Add(-time.Duration(core.Int(s, "retrace_hours", 24)) * time.Hour).Unix()
	limit := core.Int(s, "max_destinations", 300)
	since := time.Now().Add(-7 * 24 * time.Hour).Unix()
	v6 := core.Bool(s, "trace_ipv6", true)
	filter := ""
	if !v6 {
		filter = " AND f.dst_ip NOT LIKE '%:%'"
	}
	rows, err := m.ctx.Store.Rows(`
		SELECT f.dst_ip AS ip, COUNT(*) AS n FROM flows f
		WHERE f.ts >= ? AND f.dst_ip <> ''`+filter+`
		  AND NOT EXISTS (SELECT 1 FROM path_runs r WHERE r.dst = f.dst_ip AND r.ts >= ?)
		GROUP BY f.dst_ip ORDER BY n DESC LIMIT ?`, since, stale, limit)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, per)
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		if !m.worthTracing(ip) {
			continue
		}
		out = append(out, ip)
		if len(out) >= per {
			break
		}
	}
	return out, nil
}

// save writes a trace, replacing whatever was known about that destination.
func (m *Module) save(t Trace) error {
	now := t.TS.Unix()
	if err := m.ctx.Store.Exec(`DELETE FROM path_hops WHERE dst = ?`, t.Dst); err != nil {
		return err
	}
	for _, h := range t.Hops {
		if !h.Answered() {
			// A silent hop still occupies its position; recording it keeps the
			// numbering honest and shows the gap for what it is.
			if err := m.ctx.Store.Exec(
				`INSERT OR REPLACE INTO path_hops(dst,idx,ip,rtt_ms,first_seen,last_seen) VALUES(?,?,'',NULL,?,?)`,
				t.Dst, h.Index, now, now); err != nil {
				return err
			}
			continue
		}
		for i, ip := range h.IPs {
			rtt := -1.0
			if i < len(h.RTTs) {
				rtt = h.RTTs[i]
			}
			if err := m.ctx.Store.Exec(
				`INSERT OR REPLACE INTO path_hops(dst,idx,ip,rtt_ms,first_seen,last_seen) VALUES(?,?,?,?,?,?)`,
				t.Dst, h.Index, ip, rtt, now, now); err != nil {
				return err
			}
		}
	}
	complete := 0
	if t.Complete {
		complete = 1
	}
	return m.ctx.Store.Exec(
		`INSERT OR REPLACE INTO path_runs(dst,ts,hops,complete,err) VALUES(?,?,?,?,?)`,
		t.Dst, now, len(t.Hops), complete, t.Err)
}

// worthTracing keeps the probes pointed outwards.
//
// Three kinds of address have no route worth measuring and every one of them
// turned up in the first live run: an address inside this network, a
// multicast group, and the gateway's own global address. Tracing those costs
// twenty timed-out probes each and produces a row of nothing.
func (m *Module) worthTracing(ip string) bool {
	if ip == "" || isMulticast(ip) || isPrivate(ip) {
		return false
	}
	// The identity module knows this network's own prefixes, including the
	// delegated IPv6 one, which no fixed list of private ranges can cover.
	if m.identity != nil && m.identity.IsLocal(ip) {
		return false
	}
	return true
}

// isMulticast covers IPv4 224.0.0.0/4 and the IPv6 ff00::/8 groups, plus the
// broadcast address. Discovery traffic is full of these.
func isMulticast(ip string) bool {
	if ip == "255.255.255.255" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(ip), "ff") && strings.Contains(ip, ":") {
		return true
	}
	var first int
	if _, err := fmt.Sscanf(ip, "%d.", &first); err == nil {
		return first >= 224 && first <= 239
	}
	return false
}

func isPrivate(ip string) bool {
	switch {
	case strings.HasPrefix(ip, "10."), strings.HasPrefix(ip, "192.168."),
		strings.HasPrefix(ip, "127."), strings.HasPrefix(ip, "169.254."):
		return true
	case strings.HasPrefix(ip, "172."):
		var second int
		if _, err := fmt.Sscanf(ip, "172.%d.", &second); err == nil {
			return second >= 16 && second <= 31
		}
	case strings.HasPrefix(strings.ToLower(ip), "fd"), strings.HasPrefix(strings.ToLower(ip), "fe80:"),
		ip == "::1":
		return true
	}
	return false
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
