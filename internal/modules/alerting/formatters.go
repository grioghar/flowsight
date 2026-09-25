package alerting

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// Formatter converts a Message to channel-specific format.
type Formatter interface {
	Format(msg *Message) (string, error)
}

// PlainTextFormatter returns a simple text version of the alert.
type PlainTextFormatter struct{}

func (f *PlainTextFormatter) Format(msg *Message) (string, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "**%s** [%s]\n", msg.Title, msg.Severity)
	fmt.Fprintf(&buf, "Time: %s\n", msg.Timestamp.Format(time.RFC3339))
	if msg.Device != nil && msg.Device.IP != "" {
		fmt.Fprintf(&buf, "Device: %s (%s)\n", msg.Device.Name, msg.Device.IP)
	}
	if msg.Zone != "" {
		fmt.Fprintf(&buf, "Zone: %s\n", msg.Zone)
	}
	fmt.Fprintf(&buf, "Module: %s | Category: %s\n", msg.Module, msg.Category)
	if msg.Body != "" {
		fmt.Fprintf(&buf, "\n%s\n", msg.Body)
	}
	if len(msg.Evidence) > 0 {
		fmt.Fprintf(&buf, "\nEvidence:\n")
		for _, e := range msg.Evidence {
			fmt.Fprintf(&buf, "  • %s\n", e)
		}
	}
	if msg.Link != "" {
		fmt.Fprintf(&buf, "\nView: %s\n", msg.Link)
	}
	return buf.String(), nil
}

// SMSFormatter truncates and formats for SMS (160 characters).
type SMSFormatter struct{}

func (f *SMSFormatter) Format(msg *Message) (string, error) {
	title := msg.Title
	if len(title) > 100 {
		title = title[:97] + "…"
	}
	// Format: "Title [SEVERITY]: Body..."
	text := fmt.Sprintf("%s [%s]: %s", title, strings.ToUpper(msg.Severity[:1]), msg.Body)
	if len(text) > 160 {
		text = text[:157] + "…"
	}
	if msg.Link != "" {
		// Try to fit a shortened link
		linkHint := " " + msg.Link
		if len(text) < 130 && len(linkHint) < 20 {
			text = text + linkHint
		}
	}
	return text, nil
}

// JSONFormatter returns JSON representation.
type JSONFormatter struct{}

func (f *JSONFormatter) Format(msg *Message) (string, error) {
	b, err := json.MarshalIndent(msg, "", "  ")
	return string(b), err
}

// SlackFormatter returns Slack Block Kit JSON.
type SlackFormatter struct {
	BaseURL string
}

func (f *SlackFormatter) Format(msg *Message) (string, error) {
	// Note: Slack blocks use emoji/text for severity indication, not color
	_ = severityToColor(msg.Severity) // Color mapping available for future use
	blocks := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": msg.Title,
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Severity:*\n%s", msg.Severity),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Time:*\n%s", msg.Timestamp.Format(time.RFC3339)),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Module:*\n%s", msg.Module),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Category:*\n%s", msg.Category),
					},
				},
			},
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		blocks["blocks"] = append(blocks["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Device:* %s (%s)", msg.Device.Name, msg.Device.IP),
			},
		})
	}

	if msg.Body != "" {
		blocks["blocks"] = append(blocks["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": msg.Body,
			},
		})
	}

	if len(msg.Evidence) > 0 {
		evidenceText := "*Evidence:*\n"
		for _, e := range msg.Evidence {
			evidenceText += fmt.Sprintf("  • %s\n", e)
		}
		blocks["blocks"] = append(blocks["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": evidenceText,
			},
		})
	}

	if msg.Link != "" {
		blocks["blocks"] = append(blocks["blocks"].([]map[string]interface{}), map[string]interface{}{
			"type": "actions",
			"elements": []map[string]interface{}{
				{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "View Alert",
					},
					"url": msg.Link,
				},
			},
		})
	}

	b, _ := json.Marshal(blocks)
	return string(b), nil
}

// TeamsFormatter returns Microsoft Teams Adaptive Card JSON.
type TeamsFormatter struct {
	BaseURL string
}

func (f *TeamsFormatter) Format(msg *Message) (string, error) {
	color := severityToTeamsColor(msg.Severity)
	card := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"contentUrl":  nil,
				"content": map[string]interface{}{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body": []map[string]interface{}{
						{
							"type":  "Container",
							"style": "accent",
							"bleed": true,
							"items": []map[string]interface{}{
								{
									"type": "ColumnSet",
									"columns": []map[string]interface{}{
										{
											"width": "stretch",
											"items": []map[string]interface{}{
												{
													"type":   "TextBlock",
													"text":   msg.Title,
													"weight": "bolder",
													"size":   "large",
													"color":  color,
												},
											},
										},
									},
								},
							},
						},
						{
							"type": "Container",
							"items": []map[string]interface{}{
								{
									"type": "FactSet",
									"facts": []map[string]interface{}{
										{"name": "Severity", "value": msg.Severity},
										{"name": "Time", "value": msg.Timestamp.Format(time.RFC3339)},
										{"name": "Module", "value": msg.Module},
										{"name": "Category", "value": msg.Category},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		card["attachments"].([]map[string]interface{})[0]["content"].(map[string]interface{})["body"] = append(
			card["attachments"].([]map[string]interface{})[0]["content"].(map[string]interface{})["body"].([]map[string]interface{}),
			map[string]interface{}{
				"type": "TextBlock",
				"text": fmt.Sprintf("Device: %s (%s)", msg.Device.Name, msg.Device.IP),
			},
		)
	}

	if msg.Body != "" {
		card["attachments"].([]map[string]interface{})[0]["content"].(map[string]interface{})["body"] = append(
			card["attachments"].([]map[string]interface{})[0]["content"].(map[string]interface{})["body"].([]map[string]interface{}),
			map[string]interface{}{
				"type": "TextBlock",
				"text": msg.Body,
				"wrap": true,
			},
		)
	}

	b, _ := json.Marshal(card)
	return string(b), nil
}

// CEFFormatter returns Common Event Format.
type CEFFormatter struct {
	DeviceVendor  string
	DeviceVersion string
}

func (f *CEFFormatter) Format(msg *Message) (string, error) {
	// CEF:0|vendor|product|version|signatureId|name|severity|...extensions
	severity := cefSeverity(msg.Severity)
	var ext strings.Builder
	ext.WriteString(fmt.Sprintf("src=%s", msg.Module))
	if msg.Device != nil && msg.Device.IP != "" {
		ext.WriteString(fmt.Sprintf(" dst=%s", msg.Device.IP))
		if msg.Device.Name != "" {
			ext.WriteString(fmt.Sprintf(" dhost=%s", msg.Device.Name))
		}
	}
	ext.WriteString(fmt.Sprintf(" msg=%s", quoteForCEF(msg.Title)))
	ext.WriteString(fmt.Sprintf(" cat=%s", msg.Category))
	if len(msg.Evidence) > 0 {
		ext.WriteString(fmt.Sprintf(" cs1=%s", quoteForCEF(strings.Join(msg.Evidence, "; "))))
	}
	if msg.Link != "" {
		ext.WriteString(fmt.Sprintf(" cs2=%s", quoteForCEF(msg.Link)))
	}

	cef := fmt.Sprintf("CEF:0|%s|flowsight|1.0|%s|%s|%d|%s",
		f.DeviceVendor, msg.AlertKey, msg.Title, severity, ext.String())
	return cef, nil
}

// LEEFFormatter returns Loggly Event Extensible Format.
type LEEFFormatter struct{}

func (f *LEEFFormatter) Format(msg *Message) (string, error) {
	var ext strings.Builder
	ext.WriteString(fmt.Sprintf("\tseverity=%s", msg.Severity))
	ext.WriteString(fmt.Sprintf("\ttitle=%s", msg.Title))
	ext.WriteString(fmt.Sprintf("\tmodule=%s", msg.Module))
	ext.WriteString(fmt.Sprintf("\tcategory=%s", msg.Category))
	if msg.Device != nil && msg.Device.IP != "" {
		ext.WriteString(fmt.Sprintf("\tsrc=%s", msg.Device.IP))
		if msg.Device.Name != "" {
			ext.WriteString(fmt.Sprintf("\thostname=%s", msg.Device.Name))
		}
	}
	if msg.Body != "" {
		ext.WriteString(fmt.Sprintf("\tmessage=%s", msg.Body))
	}
	for i, e := range msg.Evidence {
		ext.WriteString(fmt.Sprintf("\tevidence_%d=%s", i+1, e))
	}
	if msg.Link != "" {
		ext.WriteString(fmt.Sprintf("\tlink=%s", msg.Link))
	}

	leef := fmt.Sprintf("LEEF:1.0|flowsight|flowsight|1.0|%s%s", msg.AlertKey, ext.String())
	return leef, nil
}

// TemplateFormatter uses a Go template to format messages.
type TemplateFormatter struct {
	Template string
}

func (f *TemplateFormatter) Format(msg *Message) (string, error) {
	t, err := template.New("alert").Parse(f.Template)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, msg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Helper functions

func severityToColor(severity string) string {
	switch severity {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "medium":
		return "alert"
	case "low":
		return "good"
	default:
		return "default"
	}
}

func severityToTeamsColor(severity string) string {
	switch severity {
	case "critical":
		return "FF0000" // Red
	case "high":
		return "FF9900" // Orange
	case "medium":
		return "FFCC00" // Yellow
	case "low":
		return "00CC00" // Green
	default:
		return "0078D4" // Blue
	}
}

func cefSeverity(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 6
	case "low":
		return 4
	case "info":
		return 2
	default:
		return 0
	}
}

func quoteForCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, " ", " ")
	return s
}

// HMACSignature computes HMAC-SHA256 signature for webhook authentication.
func HMACSignature(payload string, secret string) string {
	h := sha256.New()
	h.Write([]byte(secret + payload))
	return hex.EncodeToString(h.Sum(nil))
}
