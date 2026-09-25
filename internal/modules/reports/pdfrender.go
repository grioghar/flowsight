package reports

// The PDF is the Markdown rendering set on pages: headings, paragraphs and
// tables, so the file a schedule mails out says what the HTML says. The
// writer is the small built-in one (Helvetica, Latin text); its job is to
// be readable, not typeset.

import (
	"bytes"
	"sort"
	"strings"
	"time"
)

// RenderPDF builds the PDF for a run from its Markdown rendering.
// Chart methods (AddBarChart, AddLineChart) are available in SimplePDF for
// rendering traffic breakdowns and timeseries; sections can be detected from
// run.SectionData and charts emitted before table content for appropriate types
// (TrafficByDevice/App/Category/Site → bar chart; ExecutiveSummary → line chart;
// DNSSummary → blocked vs allowed bars).
func (e *Engine) RenderPDF(def *Definition, run *Run) ([]byte, error) {
	pdf := NewSimplePDF()
	pdf.AddHeading(def.Name)
	pdf.AddText("Generated " + time.Now().Format("2006-01-02 15:04 MST"))
	for _, key := range def.Sections {
		sec, ok := e.sections[key]
		if !ok {
			continue
		}
		data := run.SectionData[key]
		pdf.AddHeading(sec.Title())
		if n := sec.Notes(); n != "" {
			pdf.AddText(n)
		}
		// A picture first where the section has a natural one, then the
		// same table the HTML and Markdown carry.
		for _, ch := range sectionCharts(key, data) {
			pdf.AddBarChart(ch)
		}
		var buf bytes.Buffer
		e.renderSectionMarkdown(&buf, key, data)
		appendMarkdown(pdf, buf.String(), "")
	}
	return pdf.Bytes(), nil
}

// sectionCharts picks the chart(s) a section's data supports: the top ten
// by bytes for the traffic breakdowns, blocked against allowed for DNS.
func sectionCharts(key string, data any) []BarChart {
	type item = struct {
		Label string
		Value float64
	}
	top := func(title string, items []item) []BarChart {
		if len(items) == 0 {
			return nil
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].Value > items[j].Value })
		if len(items) > 10 {
			items = items[:10]
		}
		return []BarChart{{Title: title, Items: items}}
	}
	switch v := data.(type) {
	case TrafficByDevice:
		var it []item
		for _, r := range v.Rows {
			l := r.DeviceName
			if l == "" {
				l = r.DeviceMAC
			}
			it = append(it, item{l, float64(r.BytesIn + r.BytesOut)})
		}
		return top("Traffic by device (bytes)", it)
	case TrafficByApp:
		var it []item
		for _, r := range v.Rows {
			it = append(it, item{r.App, float64(r.Bytes)})
		}
		return top("Traffic by application (bytes)", it)
	case TrafficByCategory:
		var it []item
		for _, r := range v.Rows {
			it = append(it, item{r.Category, float64(r.Bytes)})
		}
		return top("Traffic by category (bytes)", it)
	case TrafficBySite:
		var it []item
		for _, r := range v.Rows {
			it = append(it, item{r.Domain, float64(r.Bytes)})
		}
		return top("Traffic by site (bytes)", it)
	case DNSSummary:
		if v.TotalQueries == 0 {
			return nil
		}
		return []BarChart{{Title: "DNS queries", Items: []item{{"allowed", float64(v.TotalQueries - v.TotalBlocked)}, {"blocked", float64(v.TotalBlocked)}}}}
	}
	return nil
}

// markdownToPDF renders a whole Markdown document; kept for callers and
// tests that have only the text.
func markdownToPDF(title, md string) []byte {
	pdf := NewSimplePDF()
	pdf.AddHeading(title)
	pdf.AddText("Generated " + time.Now().Format("2006-01-02 15:04 MST"))
	appendMarkdown(pdf, md, title)
	return pdf.Bytes()
}

// appendMarkdown understands the subset RenderMarkdown emits: #/##/###
// headings, pipe tables with a separator row, bullet lines, emphasis
// markers, blank lines between paragraphs.
func appendMarkdown(pdf *SimplePDF, md string, title string) {
	lines := strings.Split(md, "\n")
	var para []string
	var table [][]string
	flushPara := func() {
		if len(para) > 0 {
			pdf.AddText(strings.Join(para, " "))
			para = para[:0]
		}
	}
	flushTable := func() {
		if len(table) > 1 {
			pdf.AddTable(table[0], table[1:])
		} else if len(table) == 1 {
			pdf.AddTable(table[0], nil)
		}
		table = table[:0]
	}
	first := true
	for _, raw := range lines {
		line := strings.TrimRight(raw, " ")
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "|"):
			flushPara()
			cells := strings.Split(strings.Trim(t, "|"), "|")
			sep := true
			for i := range cells {
				cells[i] = plainMD(strings.TrimSpace(cells[i]))
				if strings.Trim(cells[i], "-: ") != "" {
					sep = false
				}
			}
			if !sep {
				table = append(table, cells)
			}
		case strings.HasPrefix(t, "#"):
			flushPara()
			flushTable()
			text := plainMD(strings.TrimSpace(strings.TrimLeft(t, "#")))
			if first && strings.EqualFold(text, title) {
				first = false
				continue // the title is already on the page
			}
			first = false
			if strings.HasPrefix(t, "### ") {
				pdf.AddText(strings.ToUpper(text))
			} else {
				pdf.AddHeading(text)
			}
		case t == "":
			flushPara()
			flushTable()
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* "):
			flushPara()
			flushTable()
			pdf.AddText("• " + plainMD(t[2:]))
		default:
			flushTable()
			if strings.HasPrefix(t, "Generated ") && len(para) == 0 {
				continue
			}
			para = append(para, plainMD(t))
		}
	}
	flushPara()
	flushTable()
}

// plainMD strips the emphasis and link syntax the Markdown uses.
func plainMD(s string) string {
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "`", "")
	if strings.HasPrefix(s, "*") && strings.HasSuffix(s, "*") && len(s) > 2 {
		s = s[1 : len(s)-1]
	}
	// [text](#anchor) -> text
	for {
		i := strings.Index(s, "](")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], ")")
		k := strings.LastIndex(s[:i], "[")
		if j < 0 || k < 0 {
			break
		}
		s = s[:k] + s[k+1:i] + s[i+j+1:]
	}
	return s
}
