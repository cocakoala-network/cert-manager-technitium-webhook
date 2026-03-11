# cert-manager-technitium-webhook

A [cert-manager](https://cert-manager.io/) DNS01 webhook solver for [Technitium DNS Server](https://technitium.com/dns/).

This webhook enables cert-manager to use Technitium DNS Server for ACME DNS01 challenge validation, allowing automatic TLS certificate issuance and renewal for domains managed by Technitium DNS.

## Features

- **DNS01 ACME challenges** via Technitium DNS Server API
- **Automatic zone detection** — queries Technitium to find the correct zone
- **Explicit zone configuration** — override auto-detection when needed
- **Configurable via environment variables** — HTTP timeouts, TLS settings, solver name
- **TLS skip verify** — supports self-signed certificates on Technitium
- **Multi-architecture Docker images** — `linux/amd64` and `linux/arm64`
- **Helm chart** — easy deployment to Kubernetes

## Installation

### Prerequisites

- Kubernetes cluster (v1.24+)
- [cert-manager](https://cert-manager.io/) v1.0.0+
- Technitium DNS Server accessible from the webhook pod
- Helm v3

### Install with Helm

```bash
# Add the Helm repository
helm repo add cocakoala-network https://cocakoala-network.github.io/cert-manager-technitium-webhook
helm repo update

# Install the webhook in the cert-manager namespace
helm install cert-manager-technitium-webhook cocakoala-network/cert-manager-technitium-webhook \
  --namespace cert-manager \
  --set groupName=acme.yourdomain.com
```

### Install from OCI Registry

```bash
helm install cert-manager-technitium-webhook \
  oci://ghcr.io/cocakoala-network/cert-manager-technitium-webhook/charts/cert-manager-technitium-webhook \
  --namespace cert-manager \
  --set groupName=acme.yourdomain.com
```

## Configuration

### Step 1: Create an API Token in Technitium DNS Server

1. Log in to your Technitium DNS Server admin panel
2. Go to **Settings** → **API**
3. Create an API Token and save it

### Step 2: Create a Kubernetes Secret for the API Token

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: technitium-api-token
  namespace: cert-manager
type: Opaque
stringData:
  api-token: "your-technitium-api-token-here"
```

```bash
kubectl apply -f secret.yaml
```

### Step 3: Create a ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.yourdomain.com  # Must match Helm value
            solverName: technitium           # Must match Helm value
            config:
              serverUrl: https://your-technitium-dns-server
              zone: example.com              # Optional: explicit zone override
              ttl: 60                        # Optional: TXT record TTL (default: 60)
              authTokenSecretRef:
                name: technitium-api-token
                key: api-token
```

```bash
kubectl apply -f cluster-issuer.yaml
```

### Step 4: Request a Certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-certificate
  namespace: default
spec:
  secretName: my-certificate-tls
  dnsNames:
    - example.com
    - "*.example.com"
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
```

## Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `groupName` | API group name for the webhook solver | `acme.example.com` |
| `solverName` | Solver name registered with cert-manager | `technitium` |
| `image.repository` | Container image repository | `ghcr.io/cocakoala-network/cert-manager-technitium-webhook` |
| `image.tag` | Container image tag | Chart `appVersion` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of webhook replicas | `1` |
| `certManager.namespace` | cert-manager namespace | `cert-manager` |
| `certManager.serviceAccountName` | cert-manager service account | `cert-manager` |
| `httpClient.timeout` | HTTP request timeout | `30s` |
| `httpClient.tlsInsecureSkipVerify` | Skip TLS verification | `false` |
| `httpClient.maxIdleConns` | Max idle HTTP connections | `10` |
| `httpClient.idleConnTimeout` | Idle connection timeout | `90s` |
| `resources` | Pod resource limits/requests | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `extraEnv` | Additional environment variables | `[]` |

## Solver Config Parameters

These are set in the ClusterIssuer/Issuer `config` block:

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `serverUrl` | Technitium DNS Server API URL | **Yes** | — |
| `authTokenSecretRef.name` | Secret name containing API token | **Yes** | — |
| `authTokenSecretRef.key` | Key in the Secret | **Yes** | — |
| `zone` | DNS zone name (overrides auto-detection) | No | Auto-detected |
| `ttl` | TXT record TTL in seconds | No | `60` |

## Environment Variables

The webhook binary supports the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `GROUP_NAME` | API group name (required) | — |
| `SOLVER_NAME` | Solver name | `technitium` |
| `HTTP_TIMEOUT` | HTTP client timeout | `30s` |
| `TLS_INSECURE_SKIP_VERIFY` | Skip TLS verification | `false` |
| `HTTP_MAX_IDLE_CONNS` | Max idle connections | `10` |
| `HTTP_IDLE_CONN_TIMEOUT` | Idle connection timeout | `90s` |

## Zone Resolution

The webhook resolves the DNS zone using the following priority:

1. **Explicit zone** from solver config (`config.zone`) — most reliable
2. **Auto-detection** by querying the Technitium DNS Server API — walks up the domain hierarchy
3. **Fallback** to cert-manager's `ResolvedZone` — least reliable, may be incorrect for private DNS

> **Important:** For private/split-horizon DNS setups, always set `zone` explicitly in your solver config. cert-manager resolves zones via public DNS, which may return incorrect results for private zones.

## Troubleshooting

### Check webhook logs

```bash
kubectl logs -n cert-manager -l app.kubernetes.io/name=cert-manager-technitium-webhook
```

### Check certificate status

```bash
kubectl describe certificate <name> -n <namespace>
```

### Check challenge status

```bash
kubectl get challenges --all-namespaces
kubectl describe challenge <name> -n <namespace>
```

### Common issues

- **"No such zone was found"** — The zone auto-detection found the wrong zone. Set `zone` explicitly in your solver config.
- **Connection refused** — Ensure the Technitium DNS Server is accessible from the webhook pod. Check network policies and DNS resolution.
- **TLS errors** — If using self-signed certificates on Technitium, set `httpClient.tlsInsecureSkipVerify: true` in Helm values.

## Development

### Prerequisites

- Go 1.24+
- Docker (for building images)
- Helm v3 (for chart development)

### Build

```bash
go build -o webhook .
```

### Test

```bash
go test -v -race ./...
```

### Docker

```bash
docker build -t cert-manager-technitium-webhook:dev .
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
