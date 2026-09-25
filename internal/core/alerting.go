package core

// AlertingSend is the interface for sending notifications through configured channels.
// Implemented by the alerting module to deliver reports and alerts.
type AlertingSend interface {
	// Send delivers a message to a channel.
	// Returns nil on success, error otherwise.
	Send(channelID string, msg Message) error
}

// Message is a notification to be sent through an alerting channel.
type Message struct {
	Subject     string       // Message subject line
	Text        string       // Plain text body
	HTML        string       // HTML body
	Attachments []Attachment // File attachments
}

// Attachment is a file to be included in a notification.
type Attachment struct {
	Name string // Filename
	MIME string // Content-Type (e.g., "application/pdf")
	Bytes []byte // File contents
}
