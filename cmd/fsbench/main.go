// fsbench measures FlowSight daemon performance under load.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	dataDir  = flag.String("data-dir", "", "data directory from fsload")
	port     = flag.Int("port", 8888, "port to listen on")
	memLimit = flag.Int("mem-limit-mb", 256, "memory limit in MB")
	timeout  = flag.Duration("timeout", 30*time.Second, "request timeout")
)

type result struct {
	Route     string
	Count     int
	P50Ms     float64
	P95Ms     float64
	P99Ms     float64
	MaxMs     float64
	AvgMs     float64
	Errors    int
	PeakMemMB uint64
}

type benchmark struct {
	addr    string
	token   string
	client  *http.Client
	routes  []string
	results map[string]*result
	mu      sync.Mutex
}

func main() {
	flag.Parse()

	if *dataDir == "" {
		log.Fatal("flag -data-dir is required")
	}

	// Start daemon in subprocess with memory limit
	cmd := startDaemon(*dataDir, *memLimit, *port)
	if cmd == nil {
		log.Fatal("failed to start daemon")
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	}()

	// Wait for daemon to be ready
	b := &benchmark{
		addr:    fmt.Sprintf("localhost:%d", *port),
		token:   "benchmark-token", // dummy token
		routes:  benchmarkRoutes(),
		results: make(map[string]*result),
		client: &http.Client{
			Timeout: *timeout,
		},
	}

	if !waitForDaemon(b.addr) {
		log.Fatal("daemon did not start in time")
	}

	log.Printf("Starting benchmarks...")

	// Run benchmarks
	b.benchmark()

	// Print results
	b.printResults()
}

func startDaemon(dataDir string, memLimitMB, port int) *exec.Cmd {
	// Find flowsightd binary or build it
	cwd, _ := os.Getwd()
	daemonPath := filepath.Join(cwd, "cmd", "flowsightd", "flowsightd")

	// Try to find a built daemon
	if _, err := os.Stat(daemonPath); err != nil {
		log.Printf("Building flowsightd...")
		cmd := exec.Command("go", "build", "-o", daemonPath, "./cmd/flowsightd")
		cmd.Dir = cwd
		if err := cmd.Run(); err != nil {
			log.Printf("build failed: %v", err)
			return nil
		}
	}

	cmd := exec.Command(daemonPath,
		"-data-dir", dataDir,
		"-log-level", "warn",
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOMEMLIMIT=%dMiB", memLimitMB),
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Printf("failed to start daemon: %v", err)
		return nil
	}

	return cmd
}

func waitForDaemon(addr string) bool {
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			time.Sleep(500 * time.Millisecond) // wait for daemon to fully initialize
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func benchmarkRoutes() []string {
	return []string{
		"/api/visibility/flows?minutes=60&limit=100",
		"/api/visibility/top?hours=24&limit=50",
		"/api/visibility/abroad?hours=24",
		"/api/policy/matches?hours=24&limit=100",
		"/api/identity/hosts?hours=24&limit=100",
		"/api/dns/summary?hours=24&limit=50",
	}
}

func (b *benchmark) benchmark() {
	for _, route := range b.routes {
		log.Printf("Benchmarking %s...", route)

		var timings []float64
		var errorCount int

		// Warm up
		for i := 0; i < 3; i++ {
			_, _ = b.request(route)
		}

		// Record peak memory before tests
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		peakMem := m.Alloc

		// Run benchmark
		count := 20
		for i := 0; i < count; i++ {
			d, err := b.request(route)
			if err != nil {
				errorCount++
				log.Printf("  request error: %v", err)
			}
			timings = append(timings, d)

			// Update peak
			runtime.ReadMemStats(&m)
			if m.Alloc > peakMem {
				peakMem = m.Alloc
			}
		}

		// Compute percentiles
		sort.Float64s(timings)
		r := &result{
			Route:     route,
			Count:     count,
			Errors:    errorCount,
			PeakMemMB: peakMem / 1024 / 1024,
		}
		if len(timings) > 0 {
			r.AvgMs = mean(timings)
			r.P50Ms = percentile(timings, 50)
			r.P95Ms = percentile(timings, 95)
			r.P99Ms = percentile(timings, 99)
			r.MaxMs = timings[len(timings)-1]
		}

		b.mu.Lock()
		b.results[route] = r
		b.mu.Unlock()
	}
}

func (b *benchmark) request(path string) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("http://%s%s", b.addr, path), nil)
	if err != nil {
		return 0, err
	}

	// Add auth header (simplified)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", b.token))

	start := time.Now()
	resp, err := b.client.Do(req)
	end := time.Now()

	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Consume body
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ms := end.Sub(start).Seconds() * 1000
	return ms, nil
}

func (b *benchmark) printResults() {
	// Sort results by route
	var routes []string
	for route := range b.results {
		routes = append(routes, route)
	}
	sort.Strings(routes)

	fmt.Println("\n=== Benchmark Results ===")
	fmt.Printf("%-50s %7s %7s %7s %7s %8s %8s\n",
		"Route", "P50(ms)", "P95(ms)", "P99(ms)", "Max(ms)", "Mem(MB)", "Errors")
	fmt.Println(strings.Repeat("-", 100))

	for _, route := range routes {
		r := b.results[route]
		fmt.Printf("%-50s %7.1f %7.1f %7.1f %7.1f %8d %8d\n",
			truncate(r.Route, 50), r.P50Ms, r.P95Ms, r.P99Ms, r.MaxMs, r.PeakMemMB, r.Errors)
	}

	// Also output JSON for further analysis
	jsonOut := struct {
		Timestamp time.Time
		Results   []result
	}{
		Timestamp: time.Now(),
		Results:   make([]result, 0, len(b.results)),
	}

	for _, route := range routes {
		jsonOut.Results = append(jsonOut.Results, *b.results[route])
	}

	jsonB, _ := json.MarshalIndent(jsonOut, "", "  ")
	fmt.Printf("\nJSON output:\n%s\n", string(jsonB))
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)) * p / 100)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func truncate(s string, l int) string {
	if len(s) <= l {
		return s
	}
	return s[:l-3] + "..."
}
