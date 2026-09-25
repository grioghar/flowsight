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

// BarChart is data for a bar chart: label -> value pairs
type BarChart struct {
	Title string
	Items []struct {
		Label string
		Value float64
	}
	MaxValue float64 // if zero, computed from items
}

// AddBarChart adds a horizontal bar chart to the PDF.
// Shows the top items with labels and scaled bars.
func (p *SimplePDF) AddBarChart(chart BarChart) {
	if len(chart.Items) == 0 {
		return
	}
	p.newPageIfNeeded()
	p.currentPage.WriteString("BT /F1 14 Tf 72 ")
	p.currentPage.WriteString(fmt.Sprintf("%.0f Td (%s) Tj ET\n", p.curY, escapeForPDF(chart.Title)))
	p.curY -= 20

	// Determine max value
	maxVal := chart.MaxValue
	if maxVal == 0 {
		for _, item := range chart.Items {
			if item.Value > maxVal {
				maxVal = item.Value
			}
		}
	}
	if maxVal == 0 {
		return
	}

	// Draw bars
	barHeight := 12.0
	spacing := 4.0
	chartLeft := 100.0
	chartWidth := 400.0
	maxItems := 10

	for i, item := range chart.Items {
		if i >= maxItems {
			break
		}
		p.newPageIfNeeded()
		if p.curY < 50 {
			// Start a new page
			p.currentPage.WriteString(fmt.Sprintf("BT /F1 10 Tf 72 %.0f Td (Page %d) Tj ET\n", p.margin-10, p.pageNum))
			p.pages = append(p.pages, p.currentPage.Bytes())
			p.currentPage = &bytes.Buffer{}
			p.pageNum++
			p.curY = p.pageHeight - p.margin
		}

		// Draw label
		p.currentPage.WriteString(fmt.Sprintf("BT /F1 10 Tf 72 %.0f Td (%s) Tj ET\n", p.curY, escapeForPDF(item.Label)))

		// Draw bar using PDF rectangle
		barLen := (item.Value / maxVal) * chartWidth
		p.currentPage.WriteString(fmt.Sprintf("q\n"))
		p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f %.0f %.0f re\n", chartLeft, p.curY-barHeight, barLen, barHeight))
		p.currentPage.WriteString("0.7 0.7 0.7 rg\n") // gray fill
		p.currentPage.WriteString("f\n")
		p.currentPage.WriteString("Q\n")

		p.curY -= (barHeight + spacing)
	}
	p.curY -= 10
}

// LineChart is data for a line chart: time series points
type LineChart struct {
	Title  string
	Points []struct {
		Label string
		Value float64
	}
	MaxValue float64
}

// AddLineChart adds a simple line chart using PDF path operators.
func (p *SimplePDF) AddLineChart(chart LineChart) {
	if len(chart.Points) < 2 {
		return
	}
	p.newPageIfNeeded()
	p.currentPage.WriteString("BT /F1 14 Tf 72 ")
	p.currentPage.WriteString(fmt.Sprintf("%.0f Td (%s) Tj ET\n", p.curY, escapeForPDF(chart.Title)))
	p.curY -= 20

	// Determine max value
	maxVal := chart.MaxValue
	if maxVal == 0 {
		for _, pt := range chart.Points {
			if pt.Value > maxVal {
				maxVal = pt.Value
			}
		}
	}
	if maxVal == 0 {
		return
	}

	// Chart dimensions
	chartLeft := 100.0
	chartTop := p.curY - 10
	chartWidth := 350.0
	chartHeight := 80.0
	maxPoints := 20

	// Draw axes
	p.currentPage.WriteString("q\n")
	p.currentPage.WriteString("0.5 w\n")                                                     // line width
	p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f m\n", chartLeft, chartTop-chartHeight)) // bottom left
	p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f l\n", chartLeft, chartTop))             // top left
	p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f l\n", chartLeft+chartWidth, chartTop))  // top right
	p.currentPage.WriteString("S\n")

	// Draw points and lines
	numPts := len(chart.Points)
	if numPts > maxPoints {
		numPts = maxPoints
	}
	xStep := chartWidth / float64(numPts-1)

	if numPts > 1 {
		// Draw line connecting points
		p.currentPage.WriteString(fmt.Sprintf("%.2f w\n", 1.5)) // line width for graph
		for i := 0; i < numPts; i++ {
			x := chartLeft + float64(i)*xStep
			y := chartTop - (chart.Points[i].Value/maxVal)*chartHeight
			if i == 0 {
				p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f m\n", x, y))
			} else {
				p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f l\n", x, y))
			}
		}
		p.currentPage.WriteString("S\n")

		// Draw points
		for i := 0; i < numPts; i++ {
			x := chartLeft + float64(i)*xStep
			y := chartTop - (chart.Points[i].Value/maxVal)*chartHeight
			p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f 2 0 360 arc f\n", x, y))
		}
	}
	p.currentPage.WriteString("Q\n")

	// Draw labels for first, middle, and last points
	if numPts > 0 {
		p.currentPage.WriteString("BT /F1 8 Tf\n")
		// First point
		p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f Td (%s) Tj\n", chartLeft-20, chartTop-chartHeight-15, escapeForPDF(chart.Points[0].Label)))
		// Last point
		lastIdx := numPts - 1
		p.currentPage.WriteString(fmt.Sprintf("%.0f %.0f Td (%s) Tj\n", chartLeft+chartWidth-20, chartTop-chartHeight-15, escapeForPDF(chart.Points[lastIdx].Label)))
		p.currentPage.WriteString("ET\n")
	}

	p.curY -= (chartHeight + 40)
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
