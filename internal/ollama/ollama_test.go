package ollama_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/ollama"
)

func tagsServer(models []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":[`)
		for i, m := range models {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"name":%q}`, m)
		}
		fmt.Fprint(w, `]}`)
	}))
}

func TestListModels(t *testing.T) {
	srv := tagsServer([]string{"glm-5.2:cloud", "kimi-k2.6:cloud"})
	defer srv.Close()
	models, err := ollama.ListModels(srv.URL, "OLLAMA_API_KEY_FOR_TEST_ONLY", 5*time.Second)
	if err != nil || len(models) != 2 {
		t.Fatalf("list: %v %v", models, err)
	}
}

func TestListModelsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if _, err := ollama.ListModels(srv.URL, "OLLAMA_API_KEY_FOR_TEST_ONLY", 2*time.Second); err == nil {
		t.Fatal("500 must surface as error for the 503 fallback")
	}
	if _, err := ollama.ListModels("http://127.0.0.1:1", "OLLAMA_API_KEY_FOR_TEST_ONLY", time.Second); err == nil {
		t.Fatal("refused connection must surface as error")
	}
}

func TestComputeUpdates(t *testing.T) {
	reg := map[string]string{"glm": "glm-5.0:cloud", "kimi": "kimi-k2.6:cloud"}
	avail := []string{"glm-5.2:cloud", "glm-5.1:cloud", "kimi-k2.6:cloud"}
	updates := ollama.ComputeUpdates(reg, avail)
	u, ok := updates["glm"]
	if !ok || u.Old != "glm-5.0:cloud" || u.New != "glm-5.2:cloud" {
		t.Fatalf("max version wins: %+v", updates)
	}
	if _, ok := updates["kimi"]; ok {
		t.Fatalf("same tag must not update: %+v", updates)
	}
	if n := len(ollama.ComputeUpdates(map[string]string{"x": "x:1"}, []string{"y:2"})); n != 0 {
		t.Fatal("unknown family must not update")
	}
}
