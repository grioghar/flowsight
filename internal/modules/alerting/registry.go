package alerting

import (
	"fmt"
	"sync"
)

// Registry manages all registered channel types.
var (
	registry = struct {
		mu       sync.RWMutex
		channels map[string]ChannelType
	}{
		channels: make(map[string]ChannelType),
	}
)

// Register registers a new channel type.
func Register(ct ChannelType) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.channels[ct.Type()] = ct
}

// Get retrieves a registered channel type.
func Get(typeName string) (ChannelType, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	ct, ok := registry.channels[typeName]
	if !ok {
		return nil, fmt.Errorf("unknown channel type: %s", typeName)
	}
	return ct, nil
}

// List returns all registered channel types.
func List() []ChannelType {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	result := make([]ChannelType, 0, len(registry.channels))
	for _, ct := range registry.channels {
		result = append(result, ct)
	}
	return result
}

// init registers all built-in channel types.
func init() {
	// Chat/Consumer channels
	Register(&SlackChannel{})
	Register(&DiscordChannel{})
	Register(&TeamsChannel{})
	Register(&TelegramChannel{})
	Register(&MatrixChannel{})
	Register(&MattermostChannel{})
	Register(&RocketChatChannel{})
	Register(&GoogleChatChannel{})
	Register(&PushoverChannel{})
	Register(&PushbulletChannel{})
	Register(&NtfyChannel{})
	Register(&GotifyChannel{})
	Register(&HomeAssistantChannel{})
	Register(&SignalChannel{})

	// SMS/Voice channels
	Register(&TwilioChannel{})
	Register(&VonageChannel{})
	Register(&TelnyxChannel{})
	Register(&AWSSNSChannel{})
	Register(&PlivoChannel{})
	Register(&MessageBirdChannel{})
	Register(&ClickSendChannel{})

	// Email channels
	Register(&SMTPChannel{})
	Register(&SendGridChannel{})
	Register(&MailgunChannel{})
	Register(&AMAZONSESChannel{})
	Register(&PostmarkChannel{})

	// Incident/On-call channels
	Register(&PagerDutyChannel{})
	Register(&OpsgenieChannel{})
	Register(&SplunkOnCallChannel{})
	Register(&SquadcastChannel{})
	Register(&IncidentIOChannel{})
	Register(&XMattersChannel{})
	Register(&ZendutySChannel{})
	Register(&BetterStackChannel{})

	// SIEM/Log channels
	Register(&SyslogChannel{})
	Register(&SplunkHECChannel{})
	Register(&ElasticChannel{})
	Register(&OpenSearchChannel{})
	Register(&GraylogChannel{})
	Register(&SentinelChannel{})
	Register(&DatadogChannel{})
	Register(&SumoLogicChannel{})
	Register(&NewRelicChannel{})
	Register(&GrafanaLokiChannel{})
	Register(&QRadarChannel{})
	Register(&WazuhChannel{})
	Register(&SentryChannel{})
	Register(&CloudWatchLogsChannel{})

	// Generic channels
	Register(&WebhookChannel{})
	Register(&MQTTChannel{})
	Register(&RSSFeedChannel{})
}
