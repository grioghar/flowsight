package policy

import (
	"fmt"
	"strings"
)

// unifiedDiff is a small line diff (LCS based) for plan output. Inputs are
// configuration files, so quadratic time on a few thousand lines is fine;
// very large inputs fall back to a summary.
func unifiedDiff(a, b, name string) string {
	al, bl := strings.Split(strings.TrimRight(a, "\n"), "\n"), strings.Split(strings.TrimRight(b, "\n"), "\n")
	if a == "" {
		al = nil
	}
	if b == "" {
		bl = nil
	}
	if len(al)*len(bl) > 4_000_000 {
		return fmt.Sprintf("--- %s (current, %d lines)\n+++ %s (desired, %d lines)\n(diff too large to render)\n",
			name, len(al), name, len(bl))
	}
	n, m := len(al), len(bl)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s (current)\n+++ %s (desired)\n", name, name)
	i, j := 0, 0
	ctx := 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			if ctx < 2 {
				out.WriteString(" " + al[i] + "\n")
			}
			ctx++
			i++
			j++
		case j < m && (i >= n || lcs[i][j+1] >= lcs[i+1][j]):
			out.WriteString("+" + bl[j] + "\n")
			ctx = 0
			j++
		default:
			out.WriteString("-" + al[i] + "\n")
			ctx = 0
			i++
		}
	}
	return out.String()
}
