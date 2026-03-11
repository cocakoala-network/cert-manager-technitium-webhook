package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer creates a mock Technitium DNS Server for testing.
// It handles zone queries, record creation, and record deletion.
func newTestServer(t *testing.T, zones map[string]bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/zones/records/get":
			domain := r.URL.Query().Get("domain")
			if enabled, ok := zones[domain]; ok && enabled {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "ok",
					"response": map[string]interface{}{
						"zone": map[string]interface{}{
							"name":     domain,
							"type":     "Primary",
							"disabled": false,
						},
					},
				})
			} else if ok && !enabled {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "ok",
					"response": map[string]interface{}{
						"zone": map[string]interface{}{
							"name":     domain,
							"type":     "Primary",
							"disabled": true,
						},
					},
				})
			} else {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":       "error",
					"errorMessage": "No such zone was found: " + domain,
				})
			}

		case "/api/zones/records/add":
			if err := r.ParseForm(); err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":       "error",
					"errorMessage": "Failed to parse form",
				})
				return
			}

			zone := r.FormValue("zone")
			if _, ok := zones[zone]; !ok {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":       "error",
					"errorMessage": "No such zone was found: " + zone,
				})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
			})

		case "/api/zones/records/delete":
			if err := r.ParseForm(); err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":       "error",
					"errorMessage": "Failed to parse form",
				})
				return
			}

			zone := r.FormValue("zone")
			if _, ok := zones[zone]; !ok {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":       "error",
					"errorMessage": "No such zone was found: " + zone,
				})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
			})

		default:
			http.NotFound(w, r)
		}
	}))
}

// TestFindAuthoritativeZone verifies zone auto-detection from the Technitium API.
func TestFindAuthoritativeZone(t *testing.T) {
	zones := map[string]bool{
		"example.com":     true,
		"sub.example.com": true,
		"disabled.com":    false,
	}

	server := newTestServer(t, zones)
	defer server.Close()

	connector := newTechnitiumConnector(server.URL, "test-token", server.Client())

	tests := []struct {
		name     string
		fqdn     string
		wantZone string
		wantErr  bool
	}{
		{
			name:     "finds zone for subdomain",
			fqdn:     "_acme-challenge.app.example.com.",
			wantZone: "example.com",
		},
		{
			name:     "finds most specific zone",
			fqdn:     "_acme-challenge.sub.example.com.",
			wantZone: "sub.example.com",
		},
		{
			name:     "finds zone for direct domain",
			fqdn:     "example.com.",
			wantZone: "example.com",
		},
		{
			name:     "finds zone without trailing dot",
			fqdn:     "_acme-challenge.app.example.com",
			wantZone: "example.com",
		},
		{
			name:    "skips disabled zone",
			fqdn:    "_acme-challenge.disabled.com.",
			wantErr: true,
		},
		{
			name:    "returns error for unknown domain",
			fqdn:    "_acme-challenge.unknown.org.",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone, err := connector.FindAuthoritativeZone(tt.fqdn)
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

// TestCreateTXTRecord verifies TXT record creation via the Technitium API.
func TestCreateTXTRecord(t *testing.T) {
	zones := map[string]bool{
		"example.com": true,
	}

	server := newTestServer(t, zones)
	defer server.Close()

	connector := newTechnitiumConnector(server.URL, "test-token", server.Client())

	tests := []struct {
		name    string
		zone    string
		fqdn    string
		value   string
		ttl     int
		wantErr bool
	}{
		{
			name:  "creates record successfully",
			zone:  "example.com",
			fqdn:  "_acme-challenge.app.example.com.",
			value: "test-challenge-value",
			ttl:   60,
		},
		{
			name:  "creates record with trailing dot on zone",
			zone:  "example.com.",
			fqdn:  "_acme-challenge.app.example.com.",
			value: "test-challenge-value",
			ttl:   120,
		},
		{
			name:    "fails for unknown zone",
			zone:    "unknown.com",
			fqdn:    "_acme-challenge.app.unknown.com.",
			value:   "test-challenge-value",
			ttl:     60,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := connector.CreateTXTRecord(tt.zone, tt.fqdn, tt.value, tt.ttl)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDeleteTXTRecord verifies TXT record deletion via the Technitium API.
func TestDeleteTXTRecord(t *testing.T) {
	zones := map[string]bool{
		"example.com": true,
	}

	server := newTestServer(t, zones)
	defer server.Close()

	connector := newTechnitiumConnector(server.URL, "test-token", server.Client())

	tests := []struct {
		name    string
		zone    string
		fqdn    string
		value   string
		wantErr bool
	}{
		{
			name:  "deletes record successfully",
			zone:  "example.com",
			fqdn:  "_acme-challenge.app.example.com.",
			value: "test-challenge-value",
		},
		{
			name:  "deletes record with trailing dot on zone",
			zone:  "example.com.",
			fqdn:  "_acme-challenge.app.example.com.",
			value: "test-challenge-value",
		},
		{
			name:    "fails for unknown zone",
			zone:    "unknown.com",
			fqdn:    "_acme-challenge.app.unknown.com.",
			value:   "test-challenge-value",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := connector.DeleteTXTRecord(tt.zone, tt.fqdn, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDeleteTXTRecordNotFound verifies that deleting a non-existent record is not an error.
func TestDeleteTXTRecordNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "error",
			"errorMessage": "Record not found.",
		})
	}))
	defer server.Close()

	connector := newTechnitiumConnector(server.URL, "test-token", server.Client())

	// Deleting a record that doesn't exist should not return an error.
	err := connector.DeleteTXTRecord("example.com", "_acme-challenge.app.example.com.", "value")
	if err != nil {
		t.Fatalf("expected no error for not-found record, got: %v", err)
	}
}

// TestConnectorServerURLTrailingSlash verifies that trailing slashes are handled.
func TestConnectorServerURLTrailingSlash(t *testing.T) {
	connector := newTechnitiumConnector("https://dns.example.com/", "token", http.DefaultClient)
	if connector.serverURL != "https://dns.example.com" {
		t.Errorf("serverURL = %q, want trailing slash removed", connector.serverURL)
	}
}

// TestDoPostHTTPError verifies error handling for HTTP failures.
func TestDoPostHTTPError(t *testing.T) {
	// Use a server that immediately closes connections.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	connector := newTechnitiumConnector(server.URL, "test-token", server.Client())

	err := connector.CreateTXTRecord("example.com", "_acme-challenge.example.com.", "value", 60)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}
