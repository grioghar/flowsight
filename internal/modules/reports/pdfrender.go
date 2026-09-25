package reports

// The PDF is the Markdown rendering set on pages: headings, paragraphs and
// tables, so the file a schedule mails out says what the HTML says. The
// writer is the small built-in one (Helvetica, Latin text); its job is to
// be readable, not typeset.

import (
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
	md, err := e.RenderMarkdown(def, run)
	if err != nil {
		return nil, err
	}
	return markdownToPDF(def.Name, md), nil
}

// markdownToPDF understands the subset RenderMarkdown emits: #/##/###
// headings, pipe tables with a separator row, bullet lines, emphasis
// markers, blank lines between paragraphs.
func markdownToPDF(title, md string) []byte {
	pdf := NewSimplePDF()
	pdf.AddHeading(title)
	pdf.AddText("Generated " + time.Now().Format("2006-01-02 15:04 MST"))
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
	return pdf.Bytes()
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
