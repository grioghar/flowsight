package egress

// Which destinations are worth watching, and what to call them.
//
// The question this module answers is "what is leaving, to whom, right now",
// and the answer is only useful if the destination has a name a person
// recognises. A row saying 162.125.21.2 took four gigabytes means nothing;
// a row saying Dropbox took four gigabytes means something immediately.
//
// Classification is deliberately coarse. The groups below are the ones that
// change what you would do about a large upload: a backup service moving
// data at night is expected, the same volume going to a paste site or a
// personal mail account is not. A destination that matches nothing is still
// reported, and an unnamed one is reported more loudly, because the
// destination nobody can name is the one worth looking at.

import "strings"

// Group is a coarse class of destination.
type Group struct {
	Key   string
	Title string
	// Watch marks a group whose uploads are worth flagging by default.
	Watch bool
}

var groups = []Group{
	{"cloud-storage", "Cloud storage", true},
	{"file-transfer", "File transfer and paste", true},
	{"code-host", "Code hosting", true},
	{"webmail", "Personal mail", true},
	{"messaging", "Messaging", true},
	{"ai", "AI assistants", true},
	{"remote-access", "Remote access", true},
	{"backup", "Backup", false},
	{"media", "Media and streaming", false},
	{"telemetry", "Telemetry and analytics", false},
	{"cdn", "Content delivery", false},
	{"tunnel", "Encrypted tunnel", true},
	{"unknown", "Unnamed destination", true},
	{"other", "Other", false},
}

// suffixes maps a domain suffix to a group. A name matches the longest
// suffix that is a whole label boundary, so "api.dropbox.com" matches
// "dropbox.com" but "notdropbox.com" does not.
var suffixes = map[string]string{
	// Cloud storage and sync
	"dropbox.com": "cloud-storage", "dropboxapi.com": "cloud-storage",
	"drive.google.com": "cloud-storage", "googleapis.com": "cloud-storage",
	"onedrive.com": "cloud-storage", "1drv.com": "cloud-storage",
	"sharepoint.com": "cloud-storage", "box.com": "cloud-storage",
	"icloud.com": "cloud-storage", "icloud-content.com": "cloud-storage",
	"mega.nz": "cloud-storage", "mega.io": "cloud-storage",
	"pcloud.com": "cloud-storage", "sync.com": "cloud-storage",
	"s3.amazonaws.com": "cloud-storage", "blob.core.windows.net": "cloud-storage",
	"storage.googleapis.com": "cloud-storage", "r2.cloudflarestorage.com": "cloud-storage",
	"wasabisys.com": "cloud-storage", "digitaloceanspaces.com": "cloud-storage",

	// Anywhere a file or a secret can be dropped in one request
	"wetransfer.com": "file-transfer", "file.io": "file-transfer",
	"transfer.sh": "file-transfer", "sendgb.com": "file-transfer",
	"pastebin.com": "file-transfer", "paste.ee": "file-transfer",
	"ghostbin.com": "file-transfer", "hastebin.com": "file-transfer",
	"anonfiles.com": "file-transfer", "gofile.io": "file-transfer",
	"catbox.moe": "file-transfer", "0x0.st": "file-transfer",
	"bashupload.com": "file-transfer", "termbin.com": "file-transfer",

	"github.com": "code-host", "githubusercontent.com": "code-host",
	"gitlab.com": "code-host", "bitbucket.org": "code-host",
	"sourceforge.net": "code-host", "codeberg.org": "code-host",
	"npmjs.org": "code-host", "pypi.org": "code-host",

	"mail.google.com": "webmail", "gmail.com": "webmail",
	"outlook.com": "webmail", "outlook.office.com": "webmail",
	"mail.yahoo.com": "webmail", "proton.me": "webmail",
	"protonmail.com": "webmail", "zoho.com": "webmail",
	"mail.ru": "webmail", "yandex.ru": "webmail",

	"discord.com": "messaging", "discordapp.com": "messaging",
	"slack.com": "messaging", "telegram.org": "messaging",
	"t.me": "messaging", "web.whatsapp.com": "messaging",
	"signal.org": "messaging", "matrix.org": "messaging",
	"facebook.com": "messaging", "messenger.com": "messaging",

	"openai.com": "ai", "chatgpt.com": "ai", "anthropic.com": "ai",
	"claude.ai": "ai", "gemini.google.com": "ai", "perplexity.ai": "ai",
	"huggingface.co": "ai", "cohere.ai": "ai", "mistral.ai": "ai",

	"teamviewer.com": "remote-access", "anydesk.com": "remote-access",
	"logmein.com": "remote-access", "gotomypc.com": "remote-access",
	"splashtop.com": "remote-access", "ngrok.io": "remote-access",
	"ngrok-free.app": "remote-access", "trycloudflare.com": "remote-access",
	"tailscale.com": "remote-access", "zerotier.com": "remote-access",
	"screenconnect.com": "remote-access", "rustdesk.com": "remote-access",

	"backblaze.com": "backup", "backblazeb2.com": "backup",
	"carbonite.com": "backup", "crashplan.com": "backup",
	"idrive.com": "backup", "tarsnap.com": "backup",

	"youtube.com": "media", "googlevideo.com": "media", "netflix.com": "media",
	"nflxvideo.net": "media", "hulu.com": "media", "spotify.com": "media",
	"scdn.co": "media", "plex.tv": "media", "twitch.tv": "media",
	"ttvnw.net": "media", "roku.com": "media", "primevideo.com": "media",

	"google-analytics.com": "telemetry", "doubleclick.net": "telemetry",
	"datadoghq.com": "telemetry", "segment.io": "telemetry",
	"mixpanel.com": "telemetry", "sentry.io": "telemetry",
	"amplitude.com": "telemetry", "telemetry.mozilla.org": "telemetry",
	"crashlytics.com": "telemetry", "app-measurement.com": "telemetry",

	"cloudfront.net": "cdn", "akamaized.net": "cdn", "akamai.net": "cdn",
	"fastly.net": "cdn", "cloudflare.com": "cdn", "cdn77.org": "cdn",
	"edgesuite.net": "cdn", "llnwd.net": "cdn",
}

// tunnelPorts are the ports that carry an encrypted tunnel, whose contents no
// amount of inspection at this layer will ever reveal. Naming them as tunnels
// is the honest thing to do: everything inside is invisible by construction.
var tunnelPorts = map[int]string{
	51820: "WireGuard", 1194: "OpenVPN", 1195: "OpenVPN",
	500: "IPsec", 4500: "IPsec NAT-T", 1701: "L2TP", 1723: "PPTP",
	3478: "STUN (mesh VPN)", 41641: "Tailscale",
}

// classify names the group a destination belongs to. name may be empty, which
// is itself a finding: data is leaving to somewhere with no name at all.
func classify(name string, port int, proto string) (group, label string) {
	if t, ok := tunnelPorts[port]; ok {
		return "tunnel", t
	}
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return "unknown", ""
	}
	best, bestLen := "", 0
	for suf, g := range suffixes {
		if len(suf) <= bestLen {
			continue
		}
		if name == suf || strings.HasSuffix(name, "."+suf) {
			best, bestLen = g, len(suf)
		}
	}
	if best == "" {
		return "other", registrable(name)
	}
	return best, registrable(name)
}

// registrable trims a host to the name a person would recognise, so that
// forty hostnames under one service collapse into one row.
func registrable(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) <= 2 {
		return name
	}
	// Two labels, unless the last two are a public suffix of the form
	// "co.uk" or "com.au", in which case take three.
	last2 := parts[len(parts)-2]
	if len(last2) <= 3 && len(parts) >= 3 {
		switch last2 {
		case "co", "com", "net", "org", "gov", "ac", "edu":
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func groupTitle(key string) string {
	for _, g := range groups {
		if g.Key == key {
			return g.Title
		}
	}
	return key
}

func watchedByDefault() []string {
	var out []string
	for _, g := range groups {
		if g.Watch {
			out = append(out, g.Key)
		}
	}
	return out
}
