// fsload generates synthetic data for testing and benchmarking FlowSight.
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

var (
	devices     = flag.Int("devices", 50, "number of devices (hosts)")
	days        = flag.Int("days", 7, "days of data to generate")
	flowsPerDay = flag.Int("flows-per-device-per-day", 100, "flows per device per day")
	outDir      = flag.String("out", "", "output directory (required)")
	seed        = flag.Int64("seed", 42, "random seed for deterministic output")
)

type generator struct {
	r         *rand.Rand
	hosts     []string
	apps      []string
	domains   []string
	countries []string
	asns      []string
	store     *core.Store
}

func main() {
	flag.Parse()
	if *outDir == "" {
		log.Fatal("flag -out is required")
	}

	// Clean and prepare output directory
	os.RemoveAll(*outDir)
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatal(err)
	}

	// Open store
	st, err := core.OpenStore(*outDir)
	if err != nil {
		log.Fatal("OpenStore:", err)
	}
	defer st.Close()

	g := &generator{
		r:     rand.New(rand.NewSource(*seed)),
		store: st,
	}

	// Initialize data pools
	g.initPools()

	// Generate data
	if err := g.generate(); err != nil {
		log.Fatal("generate:", err)
	}

	// Run rollup job to pre-compute aggregations
	if err := st.Rollup(); err != nil {
		log.Fatal("Rollup:", err)
	}

	// Print stats
	stats := st.Stats()
	fmt.Printf("Generated synthetic data:\n")
	for k, v := range stats {
		fmt.Printf("  %s: %v\n", k, v)
	}
}

func (g *generator) initPools() {
	// Generate device IPs (local)
	for i := 0; i < *devices; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", 1+i/254, 2+(i%254))
		g.hosts = append(g.hosts, ip)
	}

	// Common applications
	g.apps = []string{
		"HTTP", "HTTPS", "DNS", "SSH", "SMTP", "POP3", "IMAP", "FTP",
		"Telnet", "BitTorrent", "Git", "Slack", "Zoom", "Teams",
		"YouTube", "Netflix", "Spotify", "Instagram", "Facebook", "Twitter",
		"Google", "Amazon", "CloudFront", "Akamai", "AWS", "Azure",
	}

	// Common domains
	g.domains = []string{
		"google.com", "amazon.com", "youtube.com", "facebook.com",
		"netflix.com", "spotify.com", "slack.com", "zoom.us",
		"github.com", "gitlab.com", "stackoverflow.com", "reddit.com",
		"instagram.com", "twitter.com", "discord.com", "twitch.tv",
		"example.com", "test.local", "internal.corp", "vpn.local",
	}

	// Common countries
	g.countries = []string{"US", "GB", "DE", "FR", "JP", "CN", "IN", "BR", "CA", "AU"}

	// Common ASNs
	g.asns = []string{
		"AS15169", "AS16509", "AS8075", "AS20940", "AS32590",
		"AS6561", "AS4134", "AS1299", "AS174", "AS209",
	}
}

func (g *generator) generate() error {
	start := time.Now().Add(-time.Duration(*days*24) * time.Hour)
	baseTs := start.Unix()

	batchSize := 1000
	var flowBatch []core.Flow
	var dnsBatch []core.DNSRecord
	var hostBatch []core.HostUpdate

	// Generate flows
	log.Printf("Generating %d flows per device over %d days...", *flowsPerDay, *days)
	for day := 0; day < *days; day++ {
		dayStart := baseTs + int64(day*86400)
		dayEnd := dayStart + 86400

		for _, srcIP := range g.hosts {
			for f := 0; f < *flowsPerDay; f++ {
				// Random destination - mostly external, some internal
				var dstIP string
				if g.r.Intn(100) < 20 {
					dstIP = g.hosts[g.r.Intn(len(g.hosts))]
				} else {
					// Generate external IP
					dstIP = fmt.Sprintf("%d.%d.%d.%d",
						g.r.Intn(256), g.r.Intn(256), g.r.Intn(256), g.r.Intn(256))
				}

				ts := dayStart + g.r.Int63n(86400)
				flow := core.Flow{
					TS:       ts,
					EndTS:    ts + g.r.Int63n(3600), // up to 1 hour duration
					SrcIP:    srcIP,
					SrcPort:  1024 + g.r.Intn(64512),
					DstIP:    dstIP,
					DstPort:  g.randomPort(),
					Proto:    g.randomProto(),
					App:      g.apps[g.r.Intn(len(g.apps))],
					Category: g.randomCategory(),
					Domain:   g.domains[g.r.Intn(len(g.domains))],
					BytesIn:  g.r.Int63n(1000000),
					BytesOut: g.r.Int63n(1000000),
					Packets:  g.r.Int63n(10000),
					Duration: time.Duration(g.r.Int63n(3600000000000)).Seconds(),
					Verdict:  g.randomVerdict(),
					Country:  g.countries[g.r.Intn(len(g.countries))],
					ASN:      g.asns[g.r.Intn(len(g.asns))],
					Source:   "fsload",
					Anycast:  g.r.Intn(100) < 10,
				}
				if flow.Verdict == "blocked" {
					flow.Policy = fmt.Sprintf("rule_%d", g.r.Intn(100))
				}
				flowBatch = append(flowBatch, flow)

				if len(flowBatch) >= batchSize {
					if err := g.store.AddFlows(flowBatch); err != nil {
						return fmt.Errorf("AddFlows: %w", err)
					}
					flowBatch = nil
				}
			}
		}

		// Generate DNS records (1/3 of flow count per device)
		dnsPerDay := *flowsPerDay / 3
		for _, ip := range g.hosts {
			for d := 0; d < dnsPerDay; d++ {
				ts := dayStart + g.r.Int63n(86400)
				dns := core.DNSRecord{
					TS:     ts,
					Client: ip,
					Domain: g.domains[g.r.Intn(len(g.domains))],
					QType:  g.randomQType(),
					Action: g.randomDNSAction(),
					Source: "fsload",
					MS:     g.r.Float64() * 100,
				}
				dnsBatch = append(dnsBatch, dns)

				if len(dnsBatch) >= batchSize {
					if err := g.store.AddDNS(dnsBatch); err != nil {
						return fmt.Errorf("AddDNS: %w", err)
					}
					dnsBatch = nil
				}
			}
		}

		// Generate host updates (once per day per host)
		for _, ip := range g.hosts {
			hostBatch = append(hostBatch, core.HostUpdate{
				IP:         ip,
				MAC:        g.randomMAC(),
				Name:       g.randomHostname(),
				Vendor:     g.randomVendor(),
				Zone:       "internal",
				OS:         g.randomOS(),
				DeviceType: g.randomDeviceType(),
				Source:     "fsload",
				BytesIn:    g.r.Int63n(10000000),
				BytesOut:   g.r.Int63n(10000000),
				Flows:      int64(*flowsPerDay),
				Blocked:    int64(g.r.Intn(*flowsPerDay / 10)),
				LastSeen:   dayEnd,
				IsLocal:    ptr(true),
			})

			if len(hostBatch) >= batchSize {
				if err := g.store.UpsertHosts(hostBatch); err != nil {
					return fmt.Errorf("UpsertHosts: %w", err)
				}
				hostBatch = nil
			}
		}
	}

	// Flush remaining batches
	if len(flowBatch) > 0 {
		if err := g.store.AddFlows(flowBatch); err != nil {
			return fmt.Errorf("AddFlows (final): %w", err)
		}
	}
	if len(dnsBatch) > 0 {
		if err := g.store.AddDNS(dnsBatch); err != nil {
			return fmt.Errorf("AddDNS (final): %w", err)
		}
	}
	if len(hostBatch) > 0 {
		if err := g.store.UpsertHosts(hostBatch); err != nil {
			return fmt.Errorf("UpsertHosts (final): %w", err)
		}
	}

	return nil
}

func (g *generator) randomProto() string {
	protos := []string{"tcp", "udp", "icmp"}
	return protos[g.r.Intn(len(protos))]
}

func (g *generator) randomPort() int {
	ports := []int{80, 443, 22, 25, 53, 123, 389, 636, 8080, 8443, 3306, 5432, 6379, 27017}
	if g.r.Intn(100) < 80 {
		return ports[g.r.Intn(len(ports))]
	}
	return 1024 + g.r.Intn(64512)
}

func (g *generator) randomCategory() string {
	categories := []string{
		"Social Media", "Video Streaming", "Messaging", "Malware",
		"Phishing", "Business", "Education", "Healthcare", "Finance",
		"Shopping", "Gaming", "News", "Search Engines", "CDN",
	}
	return categories[g.r.Intn(len(categories))]
}

func (g *generator) randomVerdict() string {
	verdicts := []string{"observed", "observed", "observed", "observed", "blocked"}
	return verdicts[g.r.Intn(len(verdicts))]
}

func (g *generator) randomQType() string {
	types := []string{"A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"}
	return types[g.r.Intn(len(types))]
}

func (g *generator) randomDNSAction() string {
	actions := []string{"permit", "permit", "permit", "permit", "blocked", "nxdomain"}
	return actions[g.r.Intn(len(actions))]
}

func (g *generator) randomMAC() string {
	mac := make([]byte, 6)
	for i := 0; i < 6; i++ {
		mac[i] = byte(g.r.Intn(256))
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (g *generator) randomHostname() string {
	prefixes := []string{"dev", "prod", "test", "api", "web", "db", "cache", "monitor"}
	return prefixes[g.r.Intn(len(prefixes))] + fmt.Sprintf("%d.local", g.r.Intn(1000))
}

func (g *generator) randomVendor() string {
	vendors := []string{"Apple", "Microsoft", "Linux", "Cisco", "HP", "Dell", "Samsung", "LG", "Google"}
	if g.r.Intn(100) < 20 {
		return ""
	}
	return vendors[g.r.Intn(len(vendors))]
}

func (g *generator) randomOS() string {
	oses := []string{"iOS", "Android", "Windows", "macOS", "Linux", "FreeBSD"}
	if g.r.Intn(100) < 20 {
		return ""
	}
	return oses[g.r.Intn(len(oses))]
}

func (g *generator) randomDeviceType() string {
	types := []string{"laptop", "desktop", "mobile", "printer", "router", "switch", "camera", "speaker"}
	if g.r.Intn(100) < 10 {
		return ""
	}
	return types[g.r.Intn(len(types))]
}

func ptr[T any](v T) *T {
	return &v
}
