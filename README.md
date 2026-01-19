# KeePass Operator

A Kubernetes operator that automatically creates Kubernetes Secrets from encrypted KeePass databases (`.kdbx` files).

## Overview

The KeePass Operator enables secure, automated secret management by:

- Watching `KeePassSecret` custom resources
- Decrypting KeePass vaults using configurable password sources
- Creating and managing Kubernetes Secrets from vault entries
- Supporting multiple secrets per vault with custom labels via KeePass group notes

## Features

- **KeePass Database Support**: Works with `.kdbx` files (KeePass 2.x format)
- **Flexible Password Sources**: Direct secret reference or namespace-based password lookup
- **Multi-Secret Configuration**: Create multiple Kubernetes Secrets from a single KeePass database using group notes
- **File Attachments**: Supports binary attachments as secret data
- **Owner References**: Automatic garbage collection when KeePassSecret is deleted
- **Status Conditions**: Detailed status reporting for debugging

## Installation

### Prerequisites

- Kubernetes cluster 1.26+
- Helm 3.x (for Helm installation)
- kubectl configured to access your cluster

### Using Helm

```bash
# Install from GitHub Container Registry (OCI)
helm install kubernetes-keepass-operator \
  oci://ghcr.io/seekermarcel/charts/kubernetes-keepass-operator \
  --version latest \
  --namespace kubernetes-keepass-operator-system \
  --create-namespace

# Or install from local chart (for development)
helm install kubernetes-keepass-operator ./chart \
  --namespace kubernetes-keepass-operator-system \
  --create-namespace
```


### Using Kustomize

```bash
# Install CRDs
kubectl apply -f config/crd/bases/

# Install operator
kubectl apply -k config/default/
```

## Usage

### Basic Example

1. **Create a ConfigMap with your KeePass database:**

```bash
kubectl create configmap my-keepass-db \
  --from-file=secrets.kdbx=/path/to/your/database.kdbx \
  -n my-namespace
```

2. **Create a Secret with the database password:**

```bash
kubectl create secret generic keepass-password \
  --from-literal=password='your-database-password' \
  -n my-namespace
```

3. **Create a KeePassSecret resource:**

```yaml
apiVersion: secrets.keepass.io/v1alpha1
kind: KeePassSecret
metadata:
  name: my-app-secrets
  namespace: my-namespace
spec:
  sourceRef:
    kind: ConfigMap
    name: my-keepass-db
    key: secrets.kdbx
  passwordRef:
    secretName: keepass-password
    secretKey: password
  # Optional: override the generated secret name
  # targetSecretName: custom-secret-name
  # Optional: add labels to generated secrets
  secretLabels:
    app.kubernetes.io/part-of: my-application
```

4. **Verify the generated secret:**

```bash
kubectl get secrets -n my-namespace
kubectl get keepasssecret my-app-secrets -n my-namespace -o yaml
```

### Namespace Password Lookup

For multi-namespace deployments, you can use a centralized password database:

1. **Mount domain-passwords.kdbx in the operator:**

Configure `domainPasswords.enabled: true` in the Helm values and provide the ConfigMap containing `domain-passwords.kdbx`.

2. **Set the master password:**

Create a secret containing the master password and reference it in `masterPassword.existingSecret`.

3. **Use namespace lookup in KeePassSecret:**

```yaml
apiVersion: secrets.keepass.io/v1alpha1
kind: KeePassSecret
metadata:
  name: my-secrets
  namespace: production  # Password entry title in domain-passwords.kdbx
spec:
  sourceRef:
    kind: ConfigMap
    name: my-keepass-db
    key: secrets.kdbx
  passwordRef:
    useNamespaceLookup: true
```

### Multi-Secret Configuration

Create multiple Kubernetes Secrets from a single KeePass database by adding JSON configuration to group notes:

**KeePass Group Structure:**

```
Root
├── Database Credentials/     # Notes: {"secret-name": "db-creds"}
│   ├── postgres-password
│   └── redis-password
├── TLS Certificates/         # Notes: {"secret-name": "tls-certs", "labels": {"type": "certificate"}}
│   ├── tls.crt (attachment)
│   └── tls.key (attachment)
└── API Keys/                 # No notes (uses default secret name)
    └── external-api-key
```

**Result:** Three Kubernetes Secrets: `db-creds`, `tls-certs`, and `secrets` (default).

### Secret Types Supported

| Entry Type | Behavior |
|------------|----------|
| Password entries | Entry title becomes key, password becomes value |
| Empty entries | Entry title becomes key, empty string as value |
| Attachments | Key format: `{entry-title}-{filename}`, binary content as value |

## API Reference

### KeePassSecret Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sourceRef.kind` | string | Yes | `ConfigMap` or `Secret` |
| `sourceRef.name` | string | Yes | Name of the source resource |
| `sourceRef.key` | string | Yes | Key containing the `.kdbx` file |
| `passwordRef.secretName` | string | No* | Secret containing the password |
| `passwordRef.secretKey` | string | No | Key in the secret (default: `password`) |
| `passwordRef.useNamespaceLookup` | bool | No | Use namespace-based password lookup |
| `targetSecretName` | string | No | Override default secret name |
| `secretLabels` | map | No | Additional labels for generated secrets |
| `suspend` | bool | No | Suspend reconciliation |

*Required when `useNamespaceLookup` is false.

### Status Conditions

| Condition | Description |
|-----------|-------------|
| `Ready` | Overall status of the KeePassSecret |
| `SourceAvailable` | Source ConfigMap/Secret is accessible |
| `PasswordResolved` | Password was successfully resolved |
| `Decrypted` | KeePass database was successfully decrypted |
| `SecretsCreated` | Kubernetes Secrets were created/updated |

## Development

### Prerequisites

- Go 1.24+
- Docker
- kubectl
- [Kubebuilder](https://book.kubebuilder.io/quick-start.html#installation) (optional, for scaffolding)
- A Kubernetes cluster (local or remote)
  - [kind](https://kind.sigs.k8s.io/) - recommended for local development
  - [minikube](https://minikube.sigs.k8s.io/)
  - Or any remote cluster

### Setting Up Local Development

1. **Clone the repository:**

```bash
git clone https://github.com/seekermarcel/kubernetes-keepass-operator.git
cd kubernetes-keepass-operator
```

2. **Install dependencies:**

```bash
go mod download
```

3. **Create a local Kubernetes cluster (using kind):**

```bash
kind create cluster --name keepass-dev
kubectl cluster-info --context kind-keepass-dev
```

4. **Install the CRDs:**

```bash
make install
```

5. **Run the operator locally (outside the cluster):**

```bash
make run
```

The operator will connect to your current kubectl context and start watching for `KeePassSecret` resources.

### Creating Test Resources

1. **Create a test KeePass database:**

Use KeePassXC or KeePass to create a `.kdbx` file with some test entries, or use Python:

```bash
pip install pykeepass
python3 -c "
from pykeepass import create_database
kp = create_database('test-secrets.kdbx', password='testpassword')
kp.add_entry(kp.root_group, 'database-password', 'admin', 'supersecret123')
kp.add_entry(kp.root_group, 'api-key', '', 'my-api-key-value')
kp.save()
"
```

2. **Create the test resources in Kubernetes:**

```bash
# Create namespace
kubectl create namespace test-keepass

# Create ConfigMap with the kdbx file
kubectl create configmap test-keepass-db \
  --from-file=secrets.kdbx=test-secrets.kdbx \
  -n test-keepass

# Create password secret
kubectl create secret generic keepass-password \
  --from-literal=password='testpassword' \
  -n test-keepass

# Apply a KeePassSecret CR
cat <<EOF | kubectl apply -f -
apiVersion: secrets.keepass.io/v1alpha1
kind: KeePassSecret
metadata:
  name: test-secrets
  namespace: test-keepass
spec:
  sourceRef:
    kind: ConfigMap
    name: test-keepass-db
    key: secrets.kdbx
  passwordRef:
    secretName: keepass-password
    secretKey: password
EOF
```

3. **Verify the generated secret:**

```bash
kubectl get secrets -n test-keepass
kubectl get secret test-secrets -n test-keepass -o jsonpath='{.data}' | jq
```

### Building

```bash
# Build the operator binary
make build

# Build the container image
make docker-build IMG=your-registry/kubernetes-keepass-operator:tag

# Push the image
make docker-push IMG=your-registry/kubernetes-keepass-operator:tag

# Load image into kind cluster (for local testing)
kind load docker-image your-registry/kubernetes-keepass-operator:tag --name keepass-dev
```

### Testing

```bash
# Run unit tests
make test

# Run unit tests with verbose output
go test ./... -v

# Run tests for a specific package
go test ./internal/keepass/... -v

# Run E2E tests (requires a running cluster)
make test-e2e

# Generate coverage report
make test
go tool cover -html=cover.out -o coverage.html
```

### Deploying to Local Cluster

```bash
# Deploy to the cluster (builds image and deploys)
make deploy IMG=your-registry/kubernetes-keepass-operator:tag

# Or use Helm
helm install kubernetes-keepass-operator ./chart \
  --namespace kubernetes-keepass-operator-system \
  --create-namespace \
  --set image.repository=your-registry/kubernetes-keepass-operator \
  --set image.tag=tag

# Check operator logs
kubectl logs -f deployment/kubernetes-keepass-operator -n kubernetes-keepass-operator-system
```

### Debugging

1. **Increase log verbosity:**

```bash
# When running locally
make run ARGS="--zap-log-level=debug"
```

2. **Check CRD status:**

```bash
kubectl get keepasssecret -A -o wide
kubectl describe keepasssecret <name> -n <namespace>
```

3. **Check operator events:**

```bash
kubectl get events -n <namespace> --sort-by='.lastTimestamp'
```

### Code Generation

After modifying CRD types in `api/v1alpha1/keepasssecret_types.go`:

```bash
# Regenerate DeepCopy methods and CRD manifests
make generate manifests

# Verify the generated CRD
cat config/crd/bases/secrets.keepass.io_keepasssecrets.yaml
```

### Cleanup

```bash
# Remove test resources
kubectl delete namespace test-keepass

# Uninstall CRDs
make uninstall

# Delete kind cluster
kind delete cluster --name keepass-dev
```

## Configuration

### Helm Values

| Parameter | Default | Description |
|-----------|---------|-------------|
| `replicaCount` | `1` | Number of operator replicas |
| `image.repository` | `ghcr.io/seekermarcel/kubernetes-keepass-operator` | Image repository |
| `image.tag` | `""` (chart appVersion) | Image tag |
| `domainPasswords.enabled` | `false` | Mount domain-passwords.kdbx |
| `domainPasswords.configMapName` | `domain-passwords` | ConfigMap name |
| `masterPassword.existingSecret` | `""` | Secret with master password |
| `leaderElection.enabled` | `true` | Enable leader election |

## License

Apache License 2.0
