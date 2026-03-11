package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestSolverName verifies that the solver name is configurable via environment variable.
func TestSolverName(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     string
	}{
		{
			name:     "default solver name",
			envValue: "",
			want:     defaultSolverName,
		},
		{
			name:     "custom solver name",
			envValue: "custom-solver",
			want:     "custom-solver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(EnvSolverName, tt.envValue)
			}

			solver := &technitiumDNSProviderSolver{
				solverName: getEnvOrDefault(EnvSolverName, defaultSolverName),
			}

			if got := solver.Name(); got != tt.want {
				t.Errorf("Name() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoadConfig verifies that the solver configuration is correctly parsed and validated.
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *extapi.JSON
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "solver config is required",
		},
		{
			name:    "empty JSON",
			config:  &extapi.JSON{Raw: []byte(`{}`)},
			wantErr: true,
			errMsg:  "serverUrl is required",
		},
		{
			name:    "missing authTokenSecretRef name",
			config:  &extapi.JSON{Raw: []byte(`{"serverUrl":"https://dns.example.com","authTokenSecretRef":{"key":"token"}}`)},
			wantErr: true,
			errMsg:  "authTokenSecretRef.name is required",
		},
		{
			name:    "missing authTokenSecretRef key",
			config:  &extapi.JSON{Raw: []byte(`{"serverUrl":"https://dns.example.com","authTokenSecretRef":{"name":"secret"}}`)},
			wantErr: true,
			errMsg:  "authTokenSecretRef.key is required",
		},
		{
			name: "valid config with all fields",
			config: &extapi.JSON{Raw: []byte(`{
				"serverUrl": "https://dns.example.com",
				"authTokenSecretRef": {"name": "my-secret", "key": "api-token"},
				"zone": "example.com",
				"ttl": 120
			}`)},
			wantErr: false,
		},
		{
			name: "valid config with minimal fields",
			config: &extapi.JSON{Raw: []byte(`{
				"serverUrl": "https://dns.example.com",
				"authTokenSecretRef": {"name": "my-secret", "key": "api-token"}
			}`)},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			config:  &extapi.JSON{Raw: []byte(`{invalid}`)},
			wantErr: true,
			errMsg:  "failed to decode solver config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadConfig(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.ServerURL == "" {
				t.Error("ServerURL should not be empty")
			}
		})
	}
}

// TestGetAuthToken verifies that the auth token is correctly retrieved from Kubernetes Secrets.
func TestGetAuthToken(t *testing.T) {
	tests := []struct {
		name      string
		secret    *corev1.Secret
		ref       cmmeta.SecretKeySelector
		namespace string
		wantErr   bool
		wantToken string
	}{
		{
			name: "valid secret and key",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "cert-manager",
				},
				Data: map[string][]byte{
					"api-token": []byte("my-secret-token"),
				},
			},
			ref: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: "test-secret"},
				Key:                  "api-token",
			},
			namespace: "cert-manager",
			wantToken: "my-secret-token",
		},
		{
			name: "token with whitespace is trimmed",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "cert-manager",
				},
				Data: map[string][]byte{
					"api-token": []byte("  my-token  \n"),
				},
			},
			ref: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: "test-secret"},
				Key:                  "api-token",
			},
			namespace: "cert-manager",
			wantToken: "my-token",
		},
		{
			name:   "missing secret",
			secret: nil,
			ref: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: "nonexistent"},
				Key:                  "api-token",
			},
			namespace: "cert-manager",
			wantErr:   true,
		},
		{
			name: "missing key in secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "cert-manager",
				},
				Data: map[string][]byte{
					"other-key": []byte("value"),
				},
			},
			ref: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: "test-secret"},
				Key:                  "api-token",
			},
			namespace: "cert-manager",
			wantErr:   true,
		},
		{
			name: "empty secret name",
			ref: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: ""},
				Key:                  "api-token",
			},
			namespace: "cert-manager",
			wantErr:   true,
		},
		{
			name: "empty key",
			ref: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: "test-secret"},
				Key:                  "",
			},
			namespace: "cert-manager",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var clientset *fake.Clientset
			if tt.secret != nil {
				clientset = fake.NewSimpleClientset(tt.secret)
			} else {
				clientset = fake.NewSimpleClientset()
			}

			solver := &technitiumDNSProviderSolver{
				client: clientset,
			}

			token, err := solver.getAuthToken(tt.ref, tt.namespace)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

// TestResolveZone verifies the zone resolution priority logic.
func TestResolveZone(t *testing.T) {
	// Create a mock Technitium server that responds to zone queries.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		var resp interface{}

		switch domain {
		case "example.com":
			resp = map[string]interface{}{
				"status": "ok",
				"response": map[string]interface{}{
					"zone": map[string]interface{}{
						"name":     "example.com",
						"type":     "Primary",
						"disabled": false,
					},
				},
			}
		default:
			resp = map[string]interface{}{
				"status":       "error",
				"errorMessage": "No such zone was found: " + domain,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	connector := newTechnitiumConnector(server.URL, "test-token", server.Client())

	tests := []struct {
		name     string
		cfg      technitiumDNSProviderConfig
		ch       *v1alpha1.ChallengeRequest
		wantZone string
		wantErr  bool
	}{
		{
			name: "priority 1: explicit zone from config",
			cfg: technitiumDNSProviderConfig{
				Zone: "explicit.com",
			},
			ch: &v1alpha1.ChallengeRequest{
				ResolvedFQDN: "_acme-challenge.app.example.com.",
				ResolvedZone: "com.",
			},
			wantZone: "explicit.com",
		},
		{
			name: "priority 1: explicit zone with trailing dot",
			cfg: technitiumDNSProviderConfig{
				Zone: "explicit.com.",
			},
			ch: &v1alpha1.ChallengeRequest{
				ResolvedFQDN: "_acme-challenge.app.example.com.",
				ResolvedZone: "com.",
			},
			wantZone: "explicit.com",
		},
		{
			name: "priority 2: auto-detect from Technitium API",
			cfg:  technitiumDNSProviderConfig{},
			ch: &v1alpha1.ChallengeRequest{
				ResolvedFQDN: "_acme-challenge.app.example.com.",
				ResolvedZone: "com.",
			},
			wantZone: "example.com",
		},
		{
			name: "priority 3: fallback to cert-manager resolved zone",
			cfg:  technitiumDNSProviderConfig{},
			ch: &v1alpha1.ChallengeRequest{
				ResolvedFQDN: "_acme-challenge.app.unknown.org.",
				ResolvedZone: "unknown.org.",
			},
			wantZone: "unknown.org",
		},
		{
			name: "error: no zone resolvable",
			cfg:  technitiumDNSProviderConfig{},
			ch: &v1alpha1.ChallengeRequest{
				ResolvedFQDN: "_acme-challenge.app.unknown.org.",
				ResolvedZone: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solver := &technitiumDNSProviderSolver{}

			zone, err := solver.resolveZone(connector, tt.cfg, tt.ch)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if zone != tt.wantZone {
				t.Errorf("zone = %q, want %q", zone, tt.wantZone)
			}
		})
	}
}

// TestGetEnvOrDefault verifies environment variable fallback behavior.
func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		envValue     string
		setEnv       bool
		defaultValue string
		want         string
	}{
		{
			name:         "returns env value when set",
			key:          "TEST_ENV_VAR",
			envValue:     "custom-value",
			setEnv:       true,
			defaultValue: "default",
			want:         "custom-value",
		},
		{
			name:         "returns default when env not set",
			key:          "TEST_ENV_VAR_UNSET",
			setEnv:       false,
			defaultValue: "default",
			want:         "default",
		},
		{
			name:         "returns default when env is empty",
			key:          "TEST_ENV_VAR_EMPTY",
			envValue:     "",
			setEnv:       true,
			defaultValue: "default",
			want:         "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			} else {
				os.Unsetenv(tt.key)
			}

			got := getEnvOrDefault(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvOrDefault(%q, %q) = %q, want %q", tt.key, tt.defaultValue, got, tt.want)
			}
		})
	}
}

// TestBuildHTTPClient verifies that the HTTP client is correctly configured from env vars.
func TestBuildHTTPClient(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		client := buildHTTPClient()
		if client == nil {
			t.Fatal("buildHTTPClient() returned nil")
		}
		if client.Timeout != defaultHTTPTimeout {
			t.Errorf("timeout = %v, want %v", client.Timeout, defaultHTTPTimeout)
		}
	})

	t.Run("custom timeout from env", func(t *testing.T) {
		t.Setenv(EnvHTTPTimeout, "60s")
		client := buildHTTPClient()
		if client.Timeout.Seconds() != 60 {
			t.Errorf("timeout = %v, want 60s", client.Timeout)
		}
	})

	t.Run("invalid timeout falls back to default", func(t *testing.T) {
		t.Setenv(EnvHTTPTimeout, "invalid")
		client := buildHTTPClient()
		if client.Timeout != defaultHTTPTimeout {
			t.Errorf("timeout = %v, want %v", client.Timeout, defaultHTTPTimeout)
		}
	})
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
