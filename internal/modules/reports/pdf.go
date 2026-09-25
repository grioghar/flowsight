package reports

import (
	"bytes"
	"fmt"
	"strings"
)

// SimplePDF creates a minimal PDF with text, headings, and tables.
// This is a pure-Go implementation without external dependencies.
type SimplePDF struct {
	buf         *bytes.Buffer
	pages       [][]byte
	currentPage *bytes.Buffer
	pageHeight  float64
	pageWidth   float64
	margin      float64
	curX, curY  float64
	pageNum     int
	maxPerPage  int
}

func NewSimplePDF() *SimplePDF {
	return &SimplePDF{
		buf:        &bytes.Buffer{},
		pageHeight: 11.0 * 72, // 11 inches
		pageWidth:  8.5 * 72,  // 8.5 inches
		margin:     0.5 * 72,  // 0.5 inches
		maxPerPage: 50,        // Lines per page
	}
}

// AddHeading adds a heading (smaller space for title).
func (p *SimplePDF) AddHeading(text string) {
	p.newPageIfNeeded()
	p.currentPage.WriteString(fmt.Sprintf("BT /F1 20 Tf 72 %.0f Td (%s) Tj ET\n", p.curY, escapeForPDF(text)))
	p.curY -= 30
}

// AddText adds a line of text, wrapped to the page's width.
func (p *SimplePDF) AddText(text string) {
	for _, line := range wrapText(text, 92) {
		p.newPageIfNeeded()
		p.currentPage.WriteString(fmt.Sprintf("BT /F1 12 Tf 72 %.0f Td (%s) Tj ET\n", p.curY, escapeForPDF(line)))
		p.curY -= 15
	}
}

// wrapText breaks a line on spaces so it fits the column; a single word
// longer than the column is cut.
func wrapText(s string, width int) []string {
	s = strings.TrimSpace(s)
	if len(s) <= width {
		return []string{s}
	}
	var out []string
	for len(s) > width {
		cut := strings.LastIndex(s[:width], " ")
		if cut < width/2 {
			cut = width
		}
		out = append(out, strings.TrimSpace(s[:cut]))
		s = strings.TrimSpace(s[cut:])
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// AddTable adds a simple table.
func (p *SimplePDF) AddTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	// Rough table rendering: just text lines
	line := ""
	for i, h := range headers {
		if i > 0 {
			line += " | "
		}
		line += h
	}
	p.AddText(line)
	for _, row := range rows {
		line := ""
		for i, cell := range row {
			if i > 0 {
				line += " | "
			}
			line += cell
		}
		p.AddText(line)
		if len(p.pages) >= 1 && p.currentPage == nil {
			break // Page full
		}
	}
}

func (p *SimplePDF) newPageIfNeeded() {
	if p.currentPage == nil {
		p.currentPage = &bytes.Buffer{}
		p.pageNum++
		p.curY = p.pageHeight - p.margin
	}
	if p.curY < p.margin {
		// New page
		p.currentPage.WriteString(fmt.Sprintf("BT /F1 10 Tf 72 %.0f Td (Page %d) Tj ET\n", p.margin-10, p.pageNum))
		p.pages = append(p.pages, p.currentPage.Bytes())
		p.currentPage = &bytes.Buffer{}
		p.pageNum++
		p.curY = p.pageHeight - p.margin
	}
}

// Bytes returns the PDF: one content stream per page, a correct xref for
// every object, and each page's text as its own BT/ET blocks (a text
// object cannot nest, so the pages are not wrapped in another one).
func (p *SimplePDF) Bytes() []byte {
	if p.currentPage != nil {
		p.currentPage.WriteString(fmt.Sprintf("BT /F1 10 Tf 72 %.0f Td (Page %d) Tj ET\n", p.margin-10, p.pageNum))
		p.pages = append(p.pages, p.currentPage.Bytes())
		p.currentPage = nil
	}
	if len(p.pages) == 0 {
		p.pages = append(p.pages, []byte("BT /F1 12 Tf 72 720 Td (Empty report) Tj ET\n"))
	}
	n := len(p.pages)
	objCount := 2 + 2*n // catalog, pages, n page objects, n content streams
	offsets := make([]int64, objCount+1)
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offsets[1] = int64(pdf.Len())
	fmt.Fprintf(&pdf, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offsets[2] = int64(pdf.Len())
	fmt.Fprintf(&pdf, "2 0 obj\n<< /Type /Pages /Kids [")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&pdf, "%d 0 R ", 3+i)
	}
	fmt.Fprintf(&pdf, "] /Count %d >>\nendobj\n", n)
	for i := range p.pages {
		offsets[3+i] = int64(pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Contents %d 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>\nendobj\n",
			3+i, p.pageWidth, p.pageHeight, 3+n+i)
	}
	for i, content := range p.pages {
		offsets[3+n+i] = int64(pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n<< /Length %d >>\nstream\n%sendstream\nendobj\n", 3+n+i, len(content), content)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n", objCount+1)
	fmt.Fprintf(&pdf, "0000000000 65535 f \n")
	for i := 1; i <= objCount; i++ {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", objCount+1, xref)
	return pdf.Bytes()
}

func escapeForPDF(s string) string {
	return strings.NewReplacer(
		"\\", "\\\\",
		"(", "\\(",
		")", "\\)",
	).Replace(s)
}
