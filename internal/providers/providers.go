// Package providers defines the canonical ModelClient (chat over the
// BreachPilot model response format) plus real HTTP adapters for ollama,
// opencode_go, and chatgpt (loopback proxy). Mirrors tools/providers/.
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Response is the canonical BreachPilot model response format.
type Response struct {
	Model   string         `json:"model"`
	Message string         `json:"message"`
	Usage   map[string]any `json:"usage"`
}

// Client is the canonical interface every consumer uses.
type Client interface {
	Chat(ctx context.Context, model string, messages []map[string]string) (Response, error)
	Name() string
}

// Registry maps provider id -> factory.
var Registry = map[string]func(cfg map[string]any) Client{}

// Register adds a provider adapter.
func Register(id string, f func(cfg map[string]any) Client) { Registry[id] = f }

func httpChat(ctx context.Context, url, apiKey, model string, messages []map[string]string) (Response, error) {
	body, _ := json.Marshal(map[string]any{"model": model, "messages": messages, "stream": false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	httpClient := &http.Client{Timeout: 120 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("provider chat: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Response{}, fmt.Errorf("provider chat: status %d", resp.StatusCode)
	}
	// Ollama and OpenAI-compatible both return choices/message; normalize.
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Response{}, err
	}
	msg := ""
	if m, ok := raw["message"].(map[string]any); ok {
		msg, _ = m["content"].(string)
	} else if ch, ok := raw["choices"].([]any); ok && len(ch) > 0 {
		if m, ok := ch[0].(map[string]any); ok {
			if mm, ok := m["message"].(map[string]any); ok {
				msg, _ = mm["content"].(string)
			}
		}
	}
	usage, _ := raw["usage"].(map[string]any)
	if usage == nil {
		usage = map[string]any{}
	}
	return Response{Model: model, Message: msg, Usage: usage}, nil
}

// OllamaAdapter posts to {host}/api/chat (cloud default; localhost override).
type OllamaAdapter struct{ Host, APIKey string }

func (o *OllamaAdapter) Name() string { return "ollama" }
func (o *OllamaAdapter) Chat(ctx context.Context, model string, messages []map[string]string) (Response, error) {
	return httpChat(ctx, o.Host+"/api/chat", o.APIKey, model, messages)
}

// OpenCodeGoAdapter posts OpenAI-compatible /v1/chat/completions.
type OpenCodeGoAdapter struct{ BaseURL, APIKey, DefaultModel string }

func (o *OpenCodeGoAdapter) Name() string { return "opencode_go" }
func (o *OpenCodeGoAdapter) Chat(ctx context.Context, model string, messages []map[string]string) (Response, error) {
	if model == "" {
		model = o.DefaultModel
	}
	return httpChat(ctx, o.BaseURL+"/v1/chat/completions", o.APIKey, model, messages)
}

// ChatGPTAdapter talks to the loopback oauth proxy at 127.0.0.1:10531/v1.
type ChatGPTAdapter struct{ BaseURL string }

func (c *ChatGPTAdapter) Name() string { return "chatgpt" }
func (c *ChatGPTAdapter) Chat(ctx context.Context, model string, messages []map[string]string) (Response, error) {
	return httpChat(ctx, c.BaseURL+"/v1/chat/completions", "", model, messages)
}

func init() {
	Register("ollama", func(cfg map[string]any) Client {
		host, _ := cfg["host"].(string)
		if host == "" {
			host = "https://api.ollama.com"
		}
		key, _ := cfg["api_key"].(string)
		return &OllamaAdapter{Host: host, APIKey: key}
	})
	Register("opencode_go", func(cfg map[string]any) Client {
		base, _ := cfg["base_url"].(string)
		if base == "" {
			base = "http://127.0.0.1:10532"
		}
		key, _ := cfg["api_key"].(string)
		def, _ := cfg["default_model"].(string)
		return &OpenCodeGoAdapter{BaseURL: base, APIKey: key, DefaultModel: def}
	})
	Register("chatgpt", func(cfg map[string]any) Client {
		base, _ := cfg["base_url"].(string)
		if base == "" {
			base = "http://127.0.0.1:10531"
		}
		return &ChatGPTAdapter{BaseURL: base}
	})
}
