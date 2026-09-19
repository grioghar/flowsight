package enroll

import (
	"fmt"
	"log/slog"
	"net"
)

// Allocator manages address allocation within a zone's address range.
type Allocator struct {
	network net.IPNet
	start   net.IP
	end     net.IP
	next    net.IP
	log     *slog.Logger
	used    map[string]net.IP // mac -> allocated IP
}

// NewAllocator creates an allocator for a zone.
func NewAllocator(subnet, startStr, endStr string, log *slog.Logger) *Allocator {
	_, network, _ := net.ParseCIDR(subnet)
	if network == nil {
		return nil
	}

	start := net.ParseIP(startStr)
	end := net.ParseIP(endStr)
	if start == nil || end == nil {
		return nil
	}

	// Convert to IPv4 if needed
	if start.To4() != nil {
		start = start.To4()
		end = end.To4()
	}

	return &Allocator{
		network: *network,
		start:   start,
		end:     end,
		next:    copyIP(start),
		log:     log,
		used:    map[string]net.IP{},
	}
}

// Allocate returns a free address in the range for the given MAC, or allocates
// a new one deterministically. Same MAC always gets same address.
func (a *Allocator) Allocate(mac string) (string, error) {
	if a == nil {
		return "", fmt.Errorf("allocator nil")
	}

	// Return existing allocation
	if ip, ok := a.used[mac]; ok {
		return ip.String(), nil
	}

	// Find next free address
	for ip := copyIP(a.start); ipLessOrEqual(ip, a.end); ipIncrement(ip) {
		if !a.isUsed(ip) {
			a.used[mac] = copyIP(ip)
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no free addresses in range")
}

func (a *Allocator) isUsed(ip net.IP) bool {
	for _, allocated := range a.used {
		if allocated.Equal(ip) {
			return true
		}
	}
	return false
}

// LoadReservations marks addresses that are statically reserved.
func (a *Allocator) LoadReservations(reservations map[string]string) {
	for mac, ip := range reservations {
		a.used[mac] = net.ParseIP(ip)
	}
}

// Allocations returns the current allocations as a sorted list.
func (a *Allocator) Allocations() map[string]string {
	result := map[string]string{}
	for mac, ip := range a.used {
		result[mac] = ip.String()
	}
	return result
}

// Helper functions for IP manipulation

func copyIP(ip net.IP) net.IP {
	b := make([]byte, len(ip))
	copy(b, ip)
	return net.IP(b)
}

func ipIncrement(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ipLessOrEqual(a, b net.IP) bool {
	for i := 0; i < len(a); i++ {
		if i >= len(b) {
			return false
		}
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true
}
