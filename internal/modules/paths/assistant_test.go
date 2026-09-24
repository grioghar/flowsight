package paths

import (
	"strings"
	"testing"
)

func TestModelAnswersAreParsedFromEachEnvelope(t *testing.T) {
	cases := map[string]string{
		"anthropic": `{"content":[{"type":"text","text":"Here you go:\n{\"city\":\"Quincy\",\"region\":\"WA\",\"country\":\"US\",\"lat\":47.23,\"lon\":-119.85,\"confidence\":0.8,\"reason\":\"co = Columbia\"}"}]}`,
		"openai":    `{"choices":[{"message":{"role":"assistant","content":"{\"city\":\"Quincy\",\"country\":\"US\",\"lat\":47.23,\"lon\":-119.85,\"confidence\":0.7}"}}]}`,
		"azure":     `{"choices":[{"message":{"content":"{\"city\":\"Quincy\",\"country\":\"US\",\"lat\":47.23,\"lon\":-119.85,\"confidence\":0.9}"}}]}`,
		"google":    `{"candidates":[{"content":{"parts":[{"text":"` + "```json\\n" + `{\"city\":\"Quincy\",\"country\":\"US\",\"lat\":47.23,\"lon\":-119.85,\"confidence\":0.6}` + "\\n```" + `"}]}}]}`,
		"ollama":    `{"message":{"role":"assistant","content":"{\"city\":\"Quincy\",\"country\":\"US\",\"lat\":47.23,\"lon\":-119.85,\"confidence\":0.5}"}}`,
	}
	for prov, raw := range cases {
		text, err := extractText(prov, []byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", prov, err)
		}
		g, err := parseGuess(text)
		if err != nil || g.City != "Quincy" || g.Lat < 47 || g.Lat > 48 {
			t.Fatalf("%s: %+v %v", prov, g, err)
		}
	}
	if g, err := parseGuess(`{"unknown":true,"reason":"no convention I recognise"}`); err != nil || !g.Unknown {
		t.Fatalf("a refusal is an answer: %+v %v", g, err)
	}
	if _, err := parseGuess(`I think it is somewhere in Texas.`); err == nil {
		t.Fatal("prose is not an answer")
	}
	if _, err := parseGuess(`{"city":"Nowhere","lat":0,"lon":0,"confidence":0.9}`); err == nil {
		t.Fatal("a null island answer is not usable")
	}
}

func TestAssistantIsOffWithoutAProviderOrKey(t *testing.T) {
	if (assistConfig{Provider: "off"}).on() || (assistConfig{Provider: "openai", Endpoint: "https://x"}).on() {
		t.Fatal("no key, no questions")
	}
	if !(assistConfig{Provider: "ollama", Endpoint: "http://127.0.0.1:11434/api/chat"}).on() {
		t.Fatal("a local model needs no key")
	}
	if !(assistConfig{Provider: "anthropic", Endpoint: defaultEndpoint["anthropic"], Key: "k"}).on() {
		t.Fatal("a keyed provider is on")
	}
	p := assistPrompt
	if !strings.Contains(p, "JSON only") || !strings.Contains(p, "unknown") {
		t.Fatal("the prompt must ask for JSON and allow a refusal")
	}
}
