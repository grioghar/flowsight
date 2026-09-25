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

// AddText adds a line of text.
func (p *SimplePDF) AddText(text string) {
	p.newPageIfNeeded()
	p.currentPage.WriteString(fmt.Sprintf("BT /F1 12 Tf 72 %.0f Td (%s) Tj ET\n", p.curY, escapeForPDF(text)))
	p.curY -= 15
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

// Bytes returns the PDF as bytes (very minimal PDF).
func (p *SimplePDF) Bytes() []byte {
	if p.currentPage != nil {
		p.currentPage.WriteString(fmt.Sprintf("BT /F1 10 Tf 72 %.0f Td (Page %d) Tj ET\n", p.margin-10, p.pageNum))
		p.pages = append(p.pages, p.currentPage.Bytes())
	}

	// Create minimal PDF structure
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")

	// Objects
	objOffsets := make([]int64, 10)

	// Object 1: Catalog
	objOffsets[1] = int64(pdf.Len())
	fmt.Fprintf(&pdf, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Object 2: Pages
	objOffsets[2] = int64(pdf.Len())
	fmt.Fprintf(&pdf, "2 0 obj\n<< /Type /Pages /Kids [")
	for i := 0; i < len(p.pages); i++ {
		fmt.Fprintf(&pdf, "%d 0 R ", 3+i)
	}
	fmt.Fprintf(&pdf, "] /Count %d >>\nendobj\n", len(p.pages))

	// Objects 3+: Page objects
	for i := range p.pages {
		objOffsets[3+i] = int64(pdf.Len())
		contentObjNum := 3 + len(p.pages) + i
		fmt.Fprintf(&pdf, "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Contents %d 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>\nendobj\n",
			3+i, p.pageWidth, p.pageHeight, contentObjNum)
	}

	// Content stream objects
	for i, pageContent := range p.pages {
		contentObjNum := 3 + len(p.pages) + i
		objOffsets[contentObjNum] = int64(pdf.Len())
		content := fmt.Sprintf("q\nBT\n%sET\nQ\n", string(pageContent))
		fmt.Fprintf(&pdf, "%d 0 obj\n<< /Length %d >>\nstream\n%sstream\nendobj\n",
			contentObjNum, len(content), content)
	}

	// Xref
	xrefOffset := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n", 3+2*len(p.pages))
	fmt.Fprintf(&pdf, "0000000000 65535 f \n")
	for i := 1; i < 3+2*len(p.pages); i++ {
		if i-1 < len(objOffsets) && objOffsets[i-1] > 0 {
			fmt.Fprintf(&pdf, "%010d 00000 n \n", objOffsets[i-1])
		}
	}

	// Trailer
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\n", 3+2*len(p.pages))
	fmt.Fprintf(&pdf, "startxref\n%d\n", xrefOffset)
	fmt.Fprintf(&pdf, "%%%%EOF\n")

	return pdf.Bytes()
}

func escapeForPDF(s string) string {
	return strings.NewReplacer(
		"\\", "\\\\",
		"(", "\\(",
		")", "\\)",
	).Replace(s)
}
