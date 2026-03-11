package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/klog/v2"
)

// technitiumConnector manages communication with the Technitium DNS Server API.
// It provides methods to create, delete, and query DNS records.
type technitiumConnector struct {
	// serverURL is the base URL of the Technitium DNS Server (e.g., "https://dns.example.com").
	serverURL string

	// authToken is the API authentication token for the Technitium DNS Server.
	authToken string

	// httpClient is the HTTP client used for API requests.
	httpClient *http.Client
}

// apiResponse represents the common response structure from the Technitium DNS API.
type apiResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// zoneResponse represents the response from the Technitium DNS API when querying zones.
type zoneResponse struct {
	apiResponse
	Response struct {
		Zone struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Disabled bool   `json:"disabled"`
		} `json:"zone"`
	} `json:"response"`
}

// newTechnitiumConnector creates a new connector for communicating with the
// Technitium DNS Server API.
func newTechnitiumConnector(serverURL, token string, httpClient *http.Client) *technitiumConnector {
	return &technitiumConnector{
		serverURL:  strings.TrimRight(serverURL, "/"),
		authToken:  token,
		httpClient: httpClient,
	}
}

// FindAuthoritativeZone discovers the authoritative zone for the given FQDN
// by querying the Technitium DNS Server API. It walks up the domain hierarchy
// from the most specific to the least specific, returning the first zone that
// exists and is enabled in Technitium.
//
// For example, given "_acme-challenge.app.example.com.", it will check:
//  1. _acme-challenge.app.example.com
//  2. app.example.com
//  3. example.com
//  4. com
func (c *technitiumConnector) FindAuthoritativeZone(fqdn string) (string, error) {
	domain := strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(domain, ".")

	for i := range parts {
		candidate := strings.Join(parts[i:], ".")
		klog.V(4).Infof("Checking zone candidate: %s", candidate)

		exists, err := c.zoneExists(candidate)
		if err != nil {
			klog.V(4).Infof("Error checking zone %s: %v", candidate, err)
			continue
		}

		if exists {
			klog.V(4).Infof("Found authoritative zone: %s", candidate)
			return candidate, nil
		}
	}

	return "", fmt.Errorf("no authoritative zone found for %s in Technitium DNS Server", fqdn)
}

// zoneExists checks whether a zone exists and is enabled in the Technitium DNS Server.
func (c *technitiumConnector) zoneExists(zone string) (bool, error) {
	endpoint := fmt.Sprintf("%s/api/zones/records/get", c.serverURL)

	params := url.Values{
		"token":    {c.authToken},
		"domain":   {zone},
		"listZone": {"false"},
	}

	resp, err := c.httpClient.Get(endpoint + "?" + params.Encode())
	if err != nil {
		return false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	var zoneResp zoneResponse
	if err := json.Unmarshal(body, &zoneResp); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	return zoneResp.Status == "ok" && !zoneResp.Response.Zone.Disabled, nil
}

// CreateTXTRecord creates a TXT record in the specified zone on the Technitium DNS Server.
func (c *technitiumConnector) CreateTXTRecord(zone, fqdn, value string, ttl int) error {
	domain := strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	klog.Infof("Creating TXT record: domain=%s, zone=%s, ttl=%d", domain, zone, ttl)

	endpoint := fmt.Sprintf("%s/api/zones/records/add", c.serverURL)

	data := url.Values{
		"token":     {c.authToken},
		"domain":    {domain},
		"zone":      {zone},
		"type":      {"TXT"},
		"ttl":       {fmt.Sprintf("%d", ttl)},
		"text":      {value},
		"splitText": {"false"},
	}

	apiResp, err := c.doPost(endpoint, data)
	if err != nil {
		return fmt.Errorf("failed to create TXT record: %w", err)
	}

	if apiResp.Status != "ok" {
		return fmt.Errorf("Technitium API error: %s", apiResp.ErrorMessage)
	}

	klog.Infof("Successfully created TXT record for %s in zone %s", domain, zone)
	return nil
}

// DeleteTXTRecord removes a TXT record from the specified zone on the Technitium DNS Server.
// If the record is not found (already deleted), the operation is considered successful.
func (c *technitiumConnector) DeleteTXTRecord(zone, fqdn, value string) error {
	domain := strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	klog.Infof("Deleting TXT record: domain=%s, zone=%s", domain, zone)

	endpoint := fmt.Sprintf("%s/api/zones/records/delete", c.serverURL)

	data := url.Values{
		"token":     {c.authToken},
		"domain":    {domain},
		"zone":      {zone},
		"type":      {"TXT"},
		"text":      {value},
		"splitText": {"false"},
	}

	apiResp, err := c.doPost(endpoint, data)
	if err != nil {
		return fmt.Errorf("failed to delete TXT record: %w", err)
	}

	if apiResp.Status != "ok" {
		// If the record was not found, it may have already been deleted.
		// This is not an error condition for cleanup operations.
		if strings.Contains(strings.ToLower(apiResp.ErrorMessage), "not found") {
			klog.Infof("TXT record for %s not found (may already be deleted)", domain)
			return nil
		}
		return fmt.Errorf("Technitium API error: %s", apiResp.ErrorMessage)
	}

	klog.Infof("Successfully deleted TXT record for %s in zone %s", domain, zone)
	return nil
}

// doPost sends a POST request to the Technitium DNS API and parses the response.
func (c *technitiumConnector) doPost(endpoint string, data url.Values) (*apiResponse, error) {
	resp, err := c.httpClient.PostForm(endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	return &apiResp, nil
}

// loadConfig deserializes the JSON configuration from the cert-manager
// ChallengeRequest into a technitiumDNSProviderConfig struct.
// It validates that required fields are present.
func loadConfig(cfgJSON *extapi.JSON) (technitiumDNSProviderConfig, error) {
	cfg := technitiumDNSProviderConfig{}

	if cfgJSON == nil {
		return cfg, fmt.Errorf("solver config is required but was not provided")
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to decode solver config: %w", err)
	}

	// Validate required fields.
	if cfg.ServerURL == "" {
		return cfg, fmt.Errorf("serverUrl is required in solver config")
	}

	if cfg.AuthTokenSecretRef.LocalObjectReference.Name == "" {
		return cfg, fmt.Errorf("authTokenSecretRef.name is required in solver config")
	}

	if cfg.AuthTokenSecretRef.Key == "" {
		return cfg, fmt.Errorf("authTokenSecretRef.key is required in solver config")
	}

	return cfg, nil
}
