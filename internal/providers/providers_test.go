package providers_test

// Slice 14 RED: the provider registry and response normalization must be
// pinned — adapter registration, default-model fallback, Ollama vs
// OpenAI shapes, and honest errors on bad status/payload.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/providers"
)

func TestRegistryHasAllAdapters(t *testing.T) {
	for _, id := range []string{"ollama", "opencode_go", "chatgpt"} {
		f, ok := providers.Registry[id]
		if !ok {
			t.Fatalf("provider %q not registered", id)
		}
		if got := f(map[string]any{}).Name(); got != id {
			t.Fatalf("adapter name = %q, want %q", got, id)
		}
	}
}

func TestOpenAIAndOllamaShapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hi-openai"}}],"usage":{"tokens":3}}`))
			return
		}
		_, _ = w.Write([]byte(`{"model":"m","message":{"content":"hi-ollama"},"usage":{}}`))
	}))
	defer srv.Close()

	oc := providers.OpenCodeGoAdapter{BaseURL: srv.URL, DefaultModel: "fallback"}
	res, err := oc.Chat(context.Background(), "", []map[string]string{{"role": "user", "content": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Message != "hi-openai" {
		t.Fatalf("openai shape not normalized: %+v", res)
	}
	oa := providers.OllamaAdapter{Host: srv.URL}
	res, err = oa.Chat(context.Background(), "m", []map[string]string{{"role": "user", "content": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Message != "hi-ollama" {
		t.Fatalf("ollama shape not normalized: %+v", res)
	}
}

func TestChatErrors(t *testing.T) {
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer badStatus.Close()
	oa := providers.OllamaAdapter{Host: badStatus.URL}
	if _, err := oa.Chat(context.Background(), "m", nil); err == nil {
		t.Fatal("non-200 must error")
	}
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{oops`))
	}))
	defer badJSON.Close()
	oa2 := providers.OllamaAdapter{Host: badJSON.URL}
	if _, err := oa2.Chat(context.Background(), "m", nil); err == nil {
		t.Fatal("malformed payload must error")
	}
}
