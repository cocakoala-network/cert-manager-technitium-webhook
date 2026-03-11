// Package main implements a cert-manager DNS01 webhook solver for Technitium DNS Server.
//
// This webhook enables cert-manager to use Technitium DNS Server for ACME DNS01
// challenge validation, allowing automatic TLS certificate issuance and renewal
// for domains managed by Technitium DNS.
//
// Configuration is done through environment variables and the cert-manager
// webhook solver configuration in ClusterIssuer/Issuer resources.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// Environment variable names for webhook configuration.
const (
	// EnvGroupName is the API group name used to identify this webhook solver.
	// This must match the groupName in the ClusterIssuer/Issuer webhook configuration.
	EnvGroupName = "GROUP_NAME"

	// EnvSolverName is the solver name registered with cert-manager.
	// Defaults to "technitium" if not set.
	EnvSolverName = "SOLVER_NAME"

	// EnvHTTPTimeout is the HTTP client timeout for Technitium API requests.
	// Accepts Go duration format (e.g., "30s", "1m"). Defaults to "30s".
	EnvHTTPTimeout = "HTTP_TIMEOUT"

	// EnvTLSInsecureSkipVerify controls whether to skip TLS certificate verification
	// when connecting to the Technitium DNS Server API. Set to "true" to skip.
	// Defaults to "false".
	EnvTLSInsecureSkipVerify = "TLS_INSECURE_SKIP_VERIFY"

	// EnvMaxIdleConns is the maximum number of idle HTTP connections to keep.
	// Defaults to "10".
	EnvMaxIdleConns = "HTTP_MAX_IDLE_CONNS"

	// EnvIdleConnTimeout is the maximum time an idle connection will remain idle.
	// Accepts Go duration format. Defaults to "90s".
	EnvIdleConnTimeout = "HTTP_IDLE_CONN_TIMEOUT"

	// defaultSolverName is the default name for the DNS solver.
	defaultSolverName = "technitium"

	// defaultHTTPTimeout is the default timeout for HTTP requests.
	defaultHTTPTimeout = 30 * time.Second

	// defaultMaxIdleConns is the default maximum number of idle connections.
	defaultMaxIdleConns = 10

	// defaultIdleConnTimeout is the default idle connection timeout.
	defaultIdleConnTimeout = 90 * time.Second

	// defaultTTL is the default TTL for TXT records in seconds.
	defaultTTL = 60
)

// technitiumDNSProviderConfig holds the configuration for connecting to the
// Technitium DNS Server API. This is deserialized from the webhook solver
// config in the ClusterIssuer/Issuer resource.
type technitiumDNSProviderConfig struct {
	// ServerURL is the base URL of the Technitium DNS Server API.
	// Example: "https://dns.example.com"
	ServerURL string `json:"serverUrl"`

	// AuthTokenSecretRef references a Kubernetes Secret containing the
	// Technitium DNS Server API authentication token.
	AuthTokenSecretRef cmmeta.SecretKeySelector `json:"authTokenSecretRef"`

	// Zone is the DNS zone name to use for record management.
	// If not specified, the webhook will attempt to auto-detect the zone
	// by querying the Technitium DNS Server API.
	// Example: "example.com"
	Zone string `json:"zone,omitempty"`

	// TTL is the time-to-live in seconds for created TXT records.
	// Defaults to 60 if not specified.
	TTL int `json:"ttl,omitempty"`
}

// technitiumDNSProviderSolver implements the cert-manager webhook DNS01 solver
// interface for Technitium DNS Server.
type technitiumDNSProviderSolver struct {
	// client is the Kubernetes API client used to read Secrets.
	client kubernetes.Interface

	// solverName is the name of this DNS solver, configurable via SOLVER_NAME env var.
	solverName string

	// httpClient is the HTTP client used for Technitium API requests.
	httpClient *http.Client

	// connectorFactory creates new Technitium API connectors.
	// This is injectable for testing purposes.
	connectorFactory func(serverURL, token string, httpClient *http.Client) *technitiumConnector
}

func main() {
	groupName := os.Getenv(EnvGroupName)
	if groupName == "" {
		klog.Fatal("GROUP_NAME environment variable must be set")
	}

	solver := &technitiumDNSProviderSolver{
		solverName:       getEnvOrDefault(EnvSolverName, defaultSolverName),
		httpClient:       buildHTTPClient(),
		connectorFactory: newTechnitiumConnector,
	}

	klog.Infof("Starting Technitium DNS webhook solver (group=%s, solver=%s)", groupName, solver.solverName)
	cmd.RunWebhookServer(groupName, solver)
}

// Name returns the name of this DNS solver. This is used by cert-manager
// to match the solver to the solverName in the webhook configuration.
func (s *technitiumDNSProviderSolver) Name() string {
	return s.solverName
}

// Present creates a TXT record in Technitium DNS Server for the given
// ACME DNS01 challenge. This is called by cert-manager when a new challenge
// needs to be solved.
func (s *technitiumDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Presenting challenge for %s", ch.ResolvedFQDN)

	connector, zone, ttl, err := s.buildConnector(ch)
	if err != nil {
		return fmt.Errorf("failed to build connector: %w", err)
	}

	if err := connector.CreateTXTRecord(zone, ch.ResolvedFQDN, ch.Key, ttl); err != nil {
		return fmt.Errorf("failed to create TXT record for %s: %w", ch.ResolvedFQDN, err)
	}

	klog.Infof("Successfully presented challenge for %s in zone %s", ch.ResolvedFQDN, zone)
	return nil
}

// CleanUp removes the TXT record that was created for the ACME DNS01 challenge.
// This is called by cert-manager after the challenge has been validated or has expired.
func (s *technitiumDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Cleaning up challenge for %s", ch.ResolvedFQDN)

	connector, zone, _, err := s.buildConnector(ch)
	if err != nil {
		return fmt.Errorf("failed to build connector: %w", err)
	}

	if err := connector.DeleteTXTRecord(zone, ch.ResolvedFQDN, ch.Key); err != nil {
		return fmt.Errorf("failed to delete TXT record for %s: %w", ch.ResolvedFQDN, err)
	}

	klog.Infof("Successfully cleaned up challenge for %s in zone %s", ch.ResolvedFQDN, zone)
	return nil
}

// Initialize sets up the Kubernetes client and connector factory.
// This is called once when the webhook server starts.
func (s *technitiumDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	klog.Info("Initializing Technitium DNS webhook solver")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	s.client = cl

	if s.connectorFactory == nil {
		s.connectorFactory = newTechnitiumConnector
	}

	if s.httpClient == nil {
		s.httpClient = buildHTTPClient()
	}

	klog.Info("Technitium DNS webhook solver initialized successfully")
	return nil
}

// buildConnector creates a Technitium API connector from the challenge request
// configuration. It resolves the zone, TTL, and authentication token.
func (s *technitiumDNSProviderSolver) buildConnector(ch *v1alpha1.ChallengeRequest) (*technitiumConnector, string, int, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to load config: %w", err)
	}

	token, err := s.getAuthToken(cfg.AuthTokenSecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to get auth token: %w", err)
	}

	ttl := defaultTTL
	if cfg.TTL > 0 {
		ttl = cfg.TTL
	}

	connector := s.connectorFactory(cfg.ServerURL, token, s.httpClient)

	zone, err := s.resolveZone(connector, cfg, ch)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to resolve zone: %w", err)
	}

	return connector, zone, ttl, nil
}

// resolveZone determines the correct DNS zone for the challenge.
// It uses the following priority order:
//  1. Zone explicitly set in the solver config (cfg.Zone)
//  2. Auto-detection by querying the Technitium DNS Server API
//  3. Fallback to cert-manager's ResolvedZone (least reliable)
func (s *technitiumDNSProviderSolver) resolveZone(connector *technitiumConnector, cfg technitiumDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (string, error) {
	// Priority 1: Use explicitly configured zone.
	if cfg.Zone != "" {
		zone := strings.TrimSuffix(cfg.Zone, ".")
		klog.Infof("Using configured zone: %s", zone)
		return zone, nil
	}

	// Priority 2: Auto-detect zone from Technitium DNS Server.
	klog.Infof("No zone configured, attempting auto-detection for %s", ch.ResolvedFQDN)
	zone, err := connector.FindAuthoritativeZone(ch.ResolvedFQDN)
	if err == nil {
		klog.Infof("Auto-detected zone: %s", zone)
		return zone, nil
	}
	klog.Warningf("Zone auto-detection failed: %v", err)

	// Priority 3: Fallback to cert-manager's resolved zone.
	// Note: This may be incorrect for private/split-horizon DNS setups
	// where cert-manager resolves the zone via public DNS.
	if ch.ResolvedZone != "" {
		zone = strings.TrimSuffix(ch.ResolvedZone, ".")
		klog.Warningf("Falling back to cert-manager resolved zone: %s (this may be incorrect for private DNS)", zone)
		return zone, nil
	}

	return "", fmt.Errorf("unable to determine zone for %s: auto-detection failed and no zone configured", ch.ResolvedFQDN)
}

// getAuthToken retrieves the authentication token from a Kubernetes Secret.
func (s *technitiumDNSProviderSolver) getAuthToken(ref cmmeta.SecretKeySelector, namespace string) (string, error) {
	name := ref.LocalObjectReference.Name
	key := ref.Key

	if name == "" || key == "" {
		return "", fmt.Errorf("authTokenSecretRef must specify both name and key")
	}

	klog.V(4).Infof("Retrieving auth token from secret %s/%s (key: %s)", namespace, name, key)

	secret, err := s.client.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}

	data, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", key, namespace, name)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("auth token in secret %s/%s (key: %s) is empty", namespace, name, key)
	}

	return token, nil
}

// buildHTTPClient creates an HTTP client configured from environment variables.
func buildHTTPClient() *http.Client {
	timeout := parseDurationEnv(EnvHTTPTimeout, defaultHTTPTimeout)
	maxIdleConns := parseIntEnv(EnvMaxIdleConns, defaultMaxIdleConns)
	idleConnTimeout := parseDurationEnv(EnvIdleConnTimeout, defaultIdleConnTimeout)
	insecureSkipVerify := parseBoolEnv(EnvTLSInsecureSkipVerify, false)

	if insecureSkipVerify {
		klog.Warning("TLS certificate verification is disabled (TLS_INSECURE_SKIP_VERIFY=true)")
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        maxIdleConns,
			IdleConnTimeout:     idleConnTimeout,
			DisableCompression:  true,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // Configurable for self-signed certs.
			},
		},
	}
}

// getEnvOrDefault returns the value of an environment variable, or the default
// value if the variable is not set or empty.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDurationEnv parses a duration from an environment variable.
// Returns the default value if the variable is not set or cannot be parsed.
func parseDurationEnv(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	d, err := time.ParseDuration(value)
	if err != nil {
		klog.Warningf("Invalid duration for %s=%q, using default %s: %v", key, value, defaultValue, err)
		return defaultValue
	}
	return d
}

// parseIntEnv parses an integer from an environment variable.
// Returns the default value if the variable is not set or cannot be parsed.
func parseIntEnv(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		klog.Warningf("Invalid integer for %s=%q, using default %d: %v", key, value, defaultValue, err)
		return defaultValue
	}
	return n
}

// parseBoolEnv parses a boolean from an environment variable.
// Returns the default value if the variable is not set or cannot be parsed.
func parseBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	b, err := strconv.ParseBool(value)
	if err != nil {
		klog.Warningf("Invalid boolean for %s=%q, using default %t: %v", key, value, defaultValue, err)
		return defaultValue
	}
	return b
}
